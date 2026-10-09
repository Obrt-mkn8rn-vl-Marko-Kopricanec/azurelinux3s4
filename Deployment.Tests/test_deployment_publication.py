"""Inactive publication with real private IO and explicit root-FD/UID delivery."""

import collections
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from test_deployment_policy import LIBRARIES, emitted_program, encoded, manifest


ROOT = Path(__file__).resolve().parents[1]
CAPTURES = []


class PublicationOS:
    """Only root pathname and trust UID are modeled; private filesystem IO is real."""

    def __init__(self, root):
        self.root = str(root)
        self.acquired = []
        self.closed = []

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *args, **kwargs):
        fd = os.open(self.root if path == '/' else path, flags, *args, **kwargs)
        self.acquired.append(fd)
        return fd

    def close(self, fd):
        os.close(fd)
        self.closed.append(fd)


class DeploymentPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home() / '.cache')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.store = self.root / 'var/lib/azurelinux3s4/candidates'
        self.store.mkdir(parents=True, mode=0o700)
        for parent in self.store.parents:
            if parent == self.root.parent:
                break
            parent.chmod(0o700)
        self.n = {'__name__': 'publication_private_model'}
        for name in (*LIBRARIES, 'Deployment/publication.py'):
            exec(compile((ROOT / name).read_bytes(), name, 'exec'), self.n)
        self.delivery = PublicationOS(self.root)
        self.n['dep_os'] = self.delivery
        self.n['DEP_TRUSTED_UID'] = os.geteuid()
        self.data = encoded(manifest())
        self.digest, self.contents = self.n['publication_plan'](self.data, self.n['bundle'])
        self.pending = self.store / ('.pending-' + self.digest)
        self.final = self.store / self.digest
        self.capture = None

    def publish(self, data=None):
        return self.n['publication_publish'](self.data if data is None else data, self.n['bundle'])

    def scratch(self):
        self.pending.mkdir(mode=0o700)
        (self.pending / 'publication.json').write_bytes(self.contents['publication.json'])
        (self.pending / 'publication.json').chmod(0o400)

    def snapshot(self, folder=None):
        return {str(p.relative_to(folder or self.store)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                for p in (folder or self.store).rglob('*') if p.is_file() and not p.is_symlink()}

    def refuse(self):
        with self.assertRaises((OSError, ValueError)):
            self.publish()
        self.assertFalse(self.final.exists())

    def assert_closed(self):
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_complete_five_candidates_and_original_manifest_are_published_once(self):
        result = self.publish()
        self.assertEqual(result['disposition'], 'published')
        self.assertEqual(result['stored_files'], 8)
        self.assertEqual(result['publication_sha256'], self.digest)
        self.assertTrue(result['file_and_directory_fsync_returned'])
        self.assertTrue(result['checked_closes_completed'])
        self.assertEqual(len(result['authority']), 20)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(set(self.snapshot(self.final)), set(self.contents))
        for path, raw in self.contents.items():
            self.assertEqual((self.final / path).read_bytes(), raw)
            self.assertEqual(stat.S_IMODE((self.final / path).stat().st_mode), 0o400)
        self.assertFalse(self.pending.exists())
        self.assert_closed()
        self.capture = {'result': result, 'files': {key: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for key, raw in self.contents.items()}}

    def test_idempotence_preserves_all_committed_inodes_bytes_modes_and_unrelated_bundle(self):
        self.publish(); initial = self.snapshot()
        inodes = {str(p.relative_to(self.final)): p.stat().st_ino for p in self.final.rglob('*')}
        unrelated = self.store / 'another-owner'; unrelated.mkdir(); (unrelated / 'foreign').write_text('preserve')
        result = self.publish()
        self.assertEqual(result['disposition'], 'already-present')
        self.assertEqual({str(p.relative_to(self.final)): p.stat().st_ino for p in self.final.rglob('*')}, inodes)
        self.assertEqual({key: value for key, value in self.snapshot().items() if not key.startswith('another-owner/')}, initial)
        self.assertEqual((unrelated / 'foreign').read_text(), 'preserve')
        self.assert_closed()

    def test_changed_exact_manifest_gets_a_distinct_bundle_without_replacing_old_bytes(self):
        self.publish(); initial = self.snapshot(self.final)
        value = manifest(); value['mail']['pop3s'] = True
        result = self.publish(encoded(value))
        self.assertNotEqual(result['publication_sha256'], self.digest)
        self.assertEqual(self.snapshot(self.final), initial)
        self.assertEqual(len([p for p in self.store.iterdir() if p.is_dir()]), 2)

    def test_short_writes_are_completed_and_read_back_before_publication(self):
        write = os.write
        self.delivery.write = lambda fd, raw: write(fd, raw[:17])
        self.test_complete_five_candidates_and_original_manifest_are_published_once()

    def test_zero_write_refuses_and_preserves_incomplete_unowned_marker(self):
        self.delivery.write = lambda fd, raw: 0
        self.refuse()
        self.assertEqual((self.store / '.publisher.lock').read_bytes(), b'')
        del self.delivery.write
        self.refuse()
        self.assertEqual((self.store / '.publisher.lock').read_bytes(), b'')
        self.assert_closed()

    def test_mid_payload_failure_recovers_exact_owned_prefix_and_preserves_previous_bundle(self):
        self.publish(); old = self.snapshot(self.final)
        value = manifest(); value['mail']['sieve'] = True; changed = encoded(value)
        real_write = os.write
        calls = 0
        def fail(fd, raw):
            nonlocal calls
            calls += 1
            if calls == 3:
                return real_write(fd, raw[:19])
            if calls == 4:
                raise OSError('modeled write interruption')
            return real_write(fd, raw)
        self.delivery.write = fail
        with self.assertRaises(OSError): self.publish(changed)
        del self.delivery.write
        result = self.publish(changed)
        self.assertEqual(result['disposition'], 'recovered')
        self.assertEqual(self.snapshot(self.final), old)
        self.assert_closed()
        self.capture = {'result': result, 'previous_unchanged': old == self.snapshot(self.final)}

    def test_owned_partial_tree_recovery_admits_all_entries_before_retiring_any(self):
        self.scratch(); (self.pending / 'manifest.json').write_bytes(self.data[:20]); (self.pending / 'manifest.json').chmod(0o600)
        (self.pending / 'candidate.json').write_bytes(b'foreign bytes'); (self.pending / 'candidate.json').chmod(0o600)
        before = self.snapshot(self.pending)
        self.refuse()
        self.assertEqual(self.snapshot(self.pending), before)
        self.assert_closed()

    def test_missing_partial_or_wrong_ownership_record_is_not_adopted(self):
        for raw in (None, b'', self.contents['publication.json'][:10], b'foreign\n'):
            with self.subTest(raw=raw):
                self.pending.mkdir(mode=0o700)
                if raw is not None:
                    p = self.pending / 'publication.json'; p.write_bytes(raw); p.chmod(0o400)
                initial = self.snapshot(self.pending)
                self.refuse(); self.assertEqual(self.snapshot(self.pending), initial)
                if raw is not None: (self.pending / 'publication.json').unlink()
                self.pending.rmdir()
        self.assert_closed()

    def test_foreign_entries_in_root_or_nested_owned_tree_refuse_without_cleanup(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                self.scratch()
                parent = self.pending
                if nested: parent = self.pending / 'ssh'; parent.mkdir(mode=0o700)
                (parent / 'foreign').write_bytes(b'foreign'); before = self.snapshot(self.pending)
                self.refuse(); self.assertEqual(self.snapshot(self.pending), before)
                (parent / 'foreign').unlink()
                if nested: parent.rmdir()
                (self.pending / 'publication.json').unlink(); self.pending.rmdir()

    def test_store_or_ancestor_symlinks_and_writable_directories_refuse(self):
        for path in (self.store, self.store.parent):
            with self.subTest(path=path):
                path.chmod(0o722); self.refuse(); path.chmod(0o700)
        self.store.rmdir(); self.store.symlink_to(self.root, target_is_directory=True)
        self.refuse(); self.store.unlink()
        self.assert_closed()

    def test_pending_symlink_fifo_and_regular_collision_are_preserved(self):
        for kind in ('link', 'fifo', 'file'):
            with self.subTest(kind=kind):
                if kind == 'link': self.pending.symlink_to(self.root)
                elif kind == 'fifo': os.mkfifo(self.pending, 0o600)
                else: self.pending.write_bytes(b'foreign')
                before = self.pending.lstat()
                self.refuse(); self.assertEqual(self.pending.lstat().st_ino, before.st_ino)
                self.pending.unlink()

    def test_complete_destination_collision_is_never_overwritten(self):
        self.final.mkdir(); (self.final / 'foreign').write_bytes(b'preserve')
        before = self.snapshot(self.final)
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(self.snapshot(self.final), before)
        self.assertFalse(self.pending.exists())

    def test_native_no_replace_retains_both_existing_directories(self):
        source = self.store / 'source'; target = self.store / 'target'
        source.mkdir(); target.mkdir(); (target / 'foreign').write_bytes(b'preserve')
        fd = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(FileExistsError): self.n['publication_rename'](fd, 'source', 'target')
        finally: os.close(fd)
        self.assertTrue(source.is_dir()); self.assertEqual((target / 'foreign').read_bytes(), b'preserve')

    def test_rename_refusal_retains_complete_pending_and_next_call_recovers(self):
        original = self.n['publication_rename']; self.n['publication_rename'] = Mock(side_effect=OSError('modeled unsupported rename'))
        self.refuse(); before = self.snapshot(self.pending)
        self.assertEqual(set(before), set(self.contents))
        self.n['publication_rename'] = original
        result = self.publish(); self.assertEqual(result['disposition'], 'recovered')
        self.assertEqual(self.snapshot(self.final), before)
        self.assert_closed()

    def test_rename_api_absence_has_no_overwriting_fallback(self):
        self.n['pub_ctypes'] = type('NoAPI', (), {'CDLL': staticmethod(lambda *args, **kwargs: object())})
        self.refuse(); self.assertTrue(self.pending.is_dir())

    def test_fsync_error_withholds_result_and_never_replaces_previous_bundle(self):
        self.publish(); before = self.snapshot(self.final)
        value = manifest(); value['mail']['pop3s'] = True
        self.delivery.fsync = Mock(side_effect=OSError('modeled fsync error'))
        with self.assertRaises(OSError): self.publish(encoded(value))
        self.assertEqual(self.snapshot(self.final), before)
        self.assert_closed()

    def test_failure_after_rename_is_not_success_and_retry_rechecks_complete_destination(self):
        original = self.n['publication_rename']
        def renamed(*args):
            original(*args)
            self.delivery.fsync = Mock(side_effect=OSError('modeled post-rename fsync error'))
        self.n['publication_rename'] = renamed
        with self.assertRaises(OSError): self.publish()
        self.assertTrue(self.final.is_dir()); self.assertFalse(self.pending.exists())
        self.assert_closed()
        del self.delivery.fsync
        result = self.publish(); self.assertEqual(result['disposition'], 'already-present')
        self.capture = {'refused_after_rename': True, 'retry': result}

    def test_checked_leaf_close_error_refuses_even_when_bytes_were_written(self):
        real_close = self.delivery.close; fired = False
        def fail(fd):
            nonlocal fired
            leaf = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if leaf and not fired:
                fired = True
                raise OSError('modeled ordinary close error')
        self.delivery.close = fail
        self.refuse(); self.assertTrue(fired); self.assert_closed()

    def test_checked_final_directory_close_error_withholds_success_receipt(self):
        real_close = self.delivery.close
        def fail(fd):
            info = os.fstat(fd); real_close(fd)
            if info.st_ino == self.store.stat().st_ino:
                raise OSError('modeled store close error')
        self.delivery.close = fail
        with self.assertRaises(OSError): self.publish()
        self.assertTrue(self.final.is_dir()); self.assert_closed()

    def test_lock_busy_refuses_without_touching_pending_or_final(self):
        (self.store / '.publisher.lock').write_bytes(self.n['PUB_LOCK']); (self.store / '.publisher.lock').chmod(0o400)
        fd = os.open(self.store / '.publisher.lock', os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); before = self.snapshot()
            self.refuse(); self.assertEqual(self.snapshot(), before)
        finally: os.close(fd)
        self.assert_closed()

    def test_foreign_lock_symlink_hardlink_or_changed_bytes_refuses(self):
        path = self.store / '.publisher.lock'; foreign = self.root / 'foreign'; foreign.write_bytes(self.n['PUB_LOCK']); foreign.chmod(0o400)
        for kind in ('link', 'hardlink', 'changed'):
            with self.subTest(kind=kind):
                if kind == 'link': path.symlink_to(foreign)
                elif kind == 'hardlink': os.link(foreign, path)
                else: path.write_bytes(b'foreign'); path.chmod(0o400)
                before = path.lstat(); self.refuse(); self.assertEqual(path.lstat().st_ino, before.st_ino); path.unlink()
        self.assertEqual(foreign.read_bytes(), self.n['PUB_LOCK'])

    def test_symlink_hardlink_fifo_and_writable_owned_payload_refuse_before_recovery(self):
        foreign = self.root / 'foreign'; foreign.write_bytes(self.data); foreign.chmod(0o400)
        self.scratch(); leaf = self.pending / 'manifest.json'
        for kind in ('link', 'hardlink', 'fifo', 'writable'):
            with self.subTest(kind=kind):
                if kind == 'link': leaf.symlink_to(foreign)
                elif kind == 'hardlink': os.link(foreign, leaf)
                elif kind == 'fifo': os.mkfifo(leaf, 0o600)
                else: leaf.write_bytes(self.data); leaf.chmod(0o622)
                before = leaf.lstat(); self.refuse(); self.assertEqual(leaf.lstat().st_ino, before.st_ino); leaf.unlink()
        self.assertEqual(foreign.read_bytes(), self.data)

    def test_missing_extra_corrupt_or_writable_final_file_refuses_without_repair(self):
        self.publish()
        path = self.final / 'manifest.json'; original = path.read_bytes()
        for kind in ('missing', 'corrupt', 'writable', 'extra'):
            with self.subTest(kind=kind):
                if kind == 'missing': path.unlink()
                elif kind == 'corrupt': path.chmod(0o600); path.write_bytes(b'corrupt'); path.chmod(0o400)
                elif kind == 'writable': path.chmod(0o600)
                else: (self.final / 'foreign').write_bytes(b'preserve')
                before = self.snapshot(self.final)
                with self.assertRaises((OSError, ValueError)): self.publish()
                self.assertEqual(self.snapshot(self.final), before)
                if kind == 'extra': (self.final / 'foreign').unlink()
                else:
                    if path.exists(): path.chmod(0o600)
                    path.write_bytes(original); path.chmod(0o400)

    def test_final_and_pending_conflict_is_not_silently_cleaned(self):
        self.publish(); self.scratch(); before = self.snapshot()
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(self.snapshot(), before)

    def test_wrong_uid_and_missing_store_refuse_without_host_ancestry_creation(self):
        self.n['DEP_TRUSTED_UID'] = os.geteuid() + 1; self.refuse()
        self.n['DEP_TRUSTED_UID'] = os.geteuid(); self.store.rmdir(); self.refuse()
        self.assertFalse(self.store.exists()); self.assert_closed()

    def test_typed_candidate_file_set_and_hash_mismatch_refuse_before_io(self):
        original = self.n['deployment_bundle']; candidate = original(self.data, self.n['bundle'])
        for kind in ('missing', 'order', 'hash', 'mode'):
            with self.subTest(kind=kind):
                result = copy.deepcopy(candidate)
                if kind == 'missing': result['files'].pop()
                elif kind == 'order': result['files'].reverse()
                elif kind == 'hash': result['files'][0]['sha256'] = '0' * 64
                else: result['files'][0]['mode'] = '0777'
                self.n['deployment_bundle'] = lambda *args: result
                self.refuse(); self.assertEqual(self.delivery.acquired, [])
        self.n['deployment_bundle'] = original

    def test_actual_eof_and_leaf_metadata_changes_refuse(self):
        self.scratch(); path = self.pending / 'manifest.json'; path.write_bytes(self.data); path.chmod(0o400)
        real_read = os.read
        def changed(fd, amount):
            chunk = real_read(fd, amount)
            if os.fstat(fd).st_ino == path.stat().st_ino and chunk:
                return b'X' + chunk[1:]
            return chunk
        self.delivery.read = changed; self.refuse(); self.assertEqual(path.read_bytes(), self.data)
        self.assert_closed()

    def test_serialization_and_directory_entry_change_is_refused(self):
        self.scratch(); real_entries = self.n['publication_entries']; counts = {}
        def changed(fd):
            result = real_entries(fd); counts[fd] = counts.get(fd, 0) + 1
            if os.fstat(fd).st_ino == self.pending.stat().st_ino and counts[fd] >= 3:
                result.add('foreign')
            return result
        self.n['publication_entries'] = changed; self.refuse(); self.assertEqual(self.snapshot(self.pending), {'publication.json': (self.contents['publication.json'], 0o400)})

    def test_entry_bound_refuses_large_unrelated_pending_tree_before_mutation(self):
        self.scratch()
        for index in range(13): (self.pending / ('foreign-' + str(index))).touch()
        before = self.snapshot(self.pending)
        self.refuse(); self.assertEqual(self.snapshot(self.pending), before)

    def test_lock_replacement_after_rename_withholds_receipt(self):
        original = self.n['publication_rename']
        def replaced(*args):
            original(*args)
            path = self.store / '.publisher.lock'; path.unlink()
            path.write_bytes(self.n['PUB_LOCK']); path.chmod(0o400)
        self.n['publication_rename'] = replaced
        with self.assertRaisesRegex(ValueError, 'lock identity changed'): self.publish()
        self.assertTrue(self.final.is_dir()); self.assert_closed()

    def test_destination_creation_between_check_and_rename_is_preserved(self):
        original = self.n['publication_rename']
        def raced(*args):
            self.final.mkdir(); (self.final / 'foreign').write_bytes(b'preserve')
            original(*args)
        self.n['publication_rename'] = raced
        with self.assertRaises(FileExistsError): self.publish()
        self.assertTrue(self.pending.is_dir())
        self.assertEqual((self.final / 'foreign').read_bytes(), b'preserve')
        self.assertEqual(set(self.snapshot(self.pending)), set(self.contents))
        self.assert_closed()

    def test_main_rejects_manifest_inside_store_before_read_or_write(self):
        self.n['dep_sys'] = type('Args', (), {'argv': ['-', self.n['PUB_STORE'] + '/manifest.json'], 'stderr': sys.stderr})
        self.n['dep_resource'] = type('NoLimits', (), {'RLIMIT_CPU': 0, 'RLIMIT_AS': 1, 'RLIMIT_CORE': 2, 'setrlimit': staticmethod(lambda *args: None)})
        self.n['deployment_read'] = Mock(side_effect=AssertionError('must not read'))
        self.assertEqual(self.n['publication_main'](self.n['bundle']), 75)
        self.n['deployment_read'].assert_not_called(); self.assertEqual(self.delivery.acquired, [])

    def test_shipped_program_and_main_dispatch_use_fixed_inactive_store(self):
        program = emitted_program()
        self.assertIn((ROOT / 'Deployment/publication.py').read_text(), program)
        self.assertEqual(program.count("PUB_STORE = '/var/lib/azurelinux3s4/candidates'"), 1)
        self.assertIn("raise SystemExit(publication_main(bundle))", program)
        script = (ROOT / 'azurelinux3s4.sh').read_text()
        self.assertIn('s4_deployment_publish "$2"', script)
        self.assertIn('[[ $1 != publish ]] || allowance=90', script)
        for args in (('--publish-deployment-candidate',), ('--publish-deployment-candidate', '/source.json', 'extra')):
            result = subprocess.run(['bash', str(ROOT / 'azurelinux3s4.sh'), *args], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout, b'')

    def test_private_whole_shipped_program_reads_manifest_and_publishes_complete_candidate(self):
        source = self.root / 'source.json'; source.write_bytes(self.data); source.chmod(0o600)
        program = emitted_program()
        seam = "action = sys.argv[1]\n"
        model = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                 '_publication_real_open = dep_os.open\n'
                 '_publication_private_root = ' + repr(str(self.root)) + '\n'
                 'class _PublicationPrivateOS:\n'
                 '    def __getattr__(self, name): return getattr(dep_os_original, name)\n'
                 '    def open(self, path, flags, *args, **kwargs): return _publication_real_open(_publication_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                 'dep_os_original = dep_os\n'
                 'dep_os = _PublicationPrivateOS()\n')
        delivered = program.replace(seam, model + seam)
        result = subprocess.run([sys.executable, '-I', '-', 'publish', '/source.json'], input=delivered.encode(), capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['disposition'], 'published')
        self.assertEqual((self.final / 'manifest.json').read_bytes(), self.data)
        self.assertEqual(source.read_bytes(), self.data)
        self.assertEqual(set(self.snapshot(self.final)), set(self.contents))
        self.capture = {'receipt': receipt, 'program_sha256': hashlib.sha256(delivered.encode()).hexdigest(), 'program_bytes': len(delivered.encode()), 'input_sha256': hashlib.sha256(self.data).hexdigest(), 'returncode': result.returncode, 'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex()}

    def test_private_whole_shipped_refusal_after_rename_has_no_json_and_preserves_input(self):
        source = self.root / 'source.json'; source.write_bytes(self.data); source.chmod(0o600)
        program = emitted_program()
        seam = "action = sys.argv[1]\n"
        model = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                 '_publication_real_open = dep_os.open\n'
                 '_publication_private_root = ' + repr(str(self.root)) + '\n'
                 'class _PublicationPrivateOS:\n'
                 '    def __getattr__(self, name): return getattr(dep_os_original, name)\n'
                 '    def open(self, path, flags, *args, **kwargs): return _publication_real_open(_publication_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                 'dep_os_original = dep_os\n'
                 'dep_os = _PublicationPrivateOS()\n')
        model += ('_publication_real_rename = publication_rename\n'
                  'def _publication_refuse_after_rename(*args):\n'
                  '    _publication_real_rename(*args)\n'
                  '    raise OSError("explicit post-rename delivery fault")\n'
                  'publication_rename = _publication_refuse_after_rename\n')
        delivered = program.replace(seam, model + seam)
        result = subprocess.run([sys.executable, '-I', '-', 'publish', '/source.json'], input=delivered.encode(), capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Inactive candidate publication refused\n')
        self.assertEqual(source.read_bytes(), self.data)
        self.assertTrue(self.final.is_dir())
        self.assertFalse(self.pending.exists())
        self.assertEqual(set(self.snapshot(self.final)), set(self.contents))
        self.capture = {'program_sha256': hashlib.sha256(delivered.encode()).hexdigest(), 'program_bytes': len(delivered.encode()), 'input_sha256': hashlib.sha256(self.data).hexdigest(), 'returncode': result.returncode, 'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex(), 'explicit_post_rename_fault_model': True, 'completed_tree_left_but_no_success': True}

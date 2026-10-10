"""Complete inactive application bundles with private IO and explicit root delivery."""

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
from unittest.mock import Mock

from test_deployment_policy import emitted_program, encoded
from test_deployment_publication import PublicationOS
from test_deployment_releases import ROOT, ReleaseFixture


class ApplicationPublicationTests(ReleaseFixture):
    def setUp(self):
        super().setUp()
        for name in ('Deployment/publication.py', 'Deployment/application_publication.py'):
            exec(compile((ROOT / name).read_bytes(), name, 'exec'), self.n)
        self.delivery = PublicationOS(self.root)
        self.n['dep_os'] = self.delivery
        self.store = self.root / 'var/lib/azurelinux3s4/application-candidates'
        self.store.mkdir(parents=True, mode=0o700)
        for parent in self.store.parents:
            if parent == self.root.parent:
                break
            parent.chmod(0o700)
        self.data = encoded(self.value)
        self.digest, self.contents = self.n['application_publication_plan'](self.data, self.n['bundle'])
        self.pending = self.store / ('.pending-' + self.digest)
        self.final = self.store / self.digest
        self.capture = None

    def publish(self):
        return self.n['application_publication_publish'](encoded(self.value), self.n['bundle'])

    def store_snapshot(self, folder=None):
        base = folder or self.store
        return {str(p.relative_to(base)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                for p in base.rglob('*') if p.is_file() and not p.is_symlink()}

    def source_snapshot(self):
        return {name: row for name, row in self.snapshot().items() if not name.startswith('var/')}

    def assert_closed(self):
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def scratch(self):
        self.pending.mkdir(mode=0o700)
        path = self.pending / 'publication.json'
        path.write_bytes(self.contents['publication.json']); path.chmod(0o400)

    def run_emitted(self, fault=''):
        self.manifest_file.write_bytes(encoded(self.value))
        original = emitted_program()
        seam = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                '_app_pub_original_os = dep_os\n'
                '_app_pub_private_root = ' + repr(str(self.root)) + '\n'
                'class _ApplicationPublicationPrivateOS:\n'
                '    def __getattr__(self, name): return getattr(_app_pub_original_os, name)\n'
                '    def open(self, path, flags, *args, **kwargs):\n'
                '        return _app_pub_original_os.open(_app_pub_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                'dep_os = _ApplicationPublicationPrivateOS()\n')
        if fault:
            seam += ('_app_pub_original_rename = publication_rename\n'
                     'def _app_pub_refuse_after_rename(*args):\n'
                     '    _app_pub_original_rename(*args)\n'
                     '    raise OSError("explicit application post-rename delivery fault")\n'
                     'publication_rename = _app_pub_refuse_after_rename\n')
        code = original.replace('action = sys.argv[1]\n', seam + 'action = sys.argv[1]\n')
        before = self.source_snapshot()
        result = subprocess.run([sys.executable, '-I', '-', 'publish-applications', '/manifest.json'],
                                input=code.encode('ascii'), capture_output=True, timeout=45, check=False)
        self.assertEqual(before, self.source_snapshot())
        self.capture = {'program': code, 'input': self.manifest_file.read_bytes().decode('ascii'),
                        'stdout': result.stdout.decode('ascii'), 'stderr': result.stderr.decode('ascii'),
                        'wait': result.returncode, 'original_program_sha256': hashlib.sha256(original.encode()).hexdigest(),
                        'explicit_post_rename_fault_model': bool(fault)}
        return result

    def test_complete_single_family_units_helper_and_original_manifest_retained(self):
        before = self.source_snapshot(); result = self.publish()
        self.assertEqual(result['stored_files'], 13)
        self.assertEqual(result['bundle'], self.n['APP_PUB_STORE'] + '/' + self.digest)
        self.assertEqual(result['disposition'], 'published')
        self.assertEqual(set(self.store_snapshot(self.final)), set(self.contents))
        self.assertEqual(result['stored_bytes'], sum(map(len, self.contents.values())))
        self.assertTrue(result['file_and_directory_fsync_returned'])
        self.assertTrue(result['checked_closes_completed'])
        self.assertEqual(len(result['authority']), 20)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(before, self.source_snapshot())
        for name, raw in self.contents.items():
            self.assertEqual((self.final / name).read_bytes(), raw)
            self.assertEqual(stat.S_IMODE((self.final / name).stat().st_mode), 0o400)
        self.assertFalse(self.pending.exists()); self.assert_closed()

    def test_dual_public_family_retains_both_exact_gateway_units(self):
        self.value['public']['ipv6'] = '2001:4860::20'
        result = self.publish(); final = self.root / result['bundle'][1:]
        self.assertEqual(result['stored_files'], 14)
        for version in (4, 6):
            self.assertTrue((final / ('systemd/mk8-dns-gateway' + str(version) + '.service')).is_file())
        self.assert_closed()

    def test_ipv6_only_public_variant_retains_only_ipv6_gateway(self):
        self.value['public'].update(ipv4=None, ipv6='2001:4860::20')
        result = self.publish(); final = self.root / result['bundle'][1:]
        self.assertEqual(result['stored_files'], 13)
        self.assertTrue((final / 'systemd/mk8-dns-gateway6.service').is_file())
        self.assertFalse((final / 'systemd/mk8-dns-gateway4.service').exists()); self.assert_closed()

    def test_intent_binds_unit_and_helper_declared_paths_modes_and_complete_bytes(self):
        intent = json.loads(self.contents['publication.json'])
        self.assertEqual(intent['format'], 'azurelinux3s4-inactive-application-candidate-v1')
        self.assertFalse(intent['activation_authorized'])
        self.assertEqual(intent['candidate']['sha256'], hashlib.sha256(self.contents['candidate.json']).hexdigest())
        self.assertEqual(len(intent['files']), 10)
        for row in intent['files']:
            self.assertEqual(row['sha256'], hashlib.sha256(self.contents[row['stored']]).hexdigest())
        helper = intent['files'][-1]
        self.assertEqual(helper['file'], 'usr/libexec/azurelinux3s4/dns-credentials.py')
        self.assertEqual(helper['mode'], '0755')
        self.assertEqual(helper['stored'], 'helpers/dns-credentials.py')
        self.assertEqual(self.contents[helper['stored']], self.n['DNS_CREDENTIAL_PROGRAM'].encode())

    def test_existing_five_file_store_constants_and_complete_default_plan_preserved(self):
        digest, contents = self.n['publication_plan'](self.data, self.n['bundle'])
        self.assertNotEqual(digest, self.digest); self.assertEqual(len(contents), 8)
        self.assertEqual(self.n['PUB_STORE'], '/var/lib/azurelinux3s4/candidates')
        self.assertEqual(tuple(name for name in contents if '/' in name), self.n['PUB_FILES'])
        self.assertEqual(json.loads(contents['publication.json'])['format'], 'azurelinux3s4-inactive-candidate-v1')
        self.assertNotEqual(self.n['PUB_LOCK'], self.n['APP_PUB_LOCK'])

    def test_application_publication_leaves_other_store_and_foreign_bundles_unchanged(self):
        other = self.store.parent / 'candidates'; other.mkdir(mode=0o700)
        marker = other / 'preserve'; marker.write_bytes(b'other owner bytes')
        foreign = self.store / 'another-owner'; foreign.mkdir(); (foreign / 'preserve').write_bytes(b'foreign')
        before = marker.stat(); self.publish()
        self.assertEqual(marker.stat(), before)  # Observe publisher effects before our own content read.
        self.assertEqual(marker.read_bytes(), b'other owner bytes')
        self.assertEqual((foreign / 'preserve').read_bytes(), b'foreign'); self.assert_closed()

    def test_idempotent_retry_preserves_complete_file_inodes_and_bytes(self):
        self.publish(); before = self.store_snapshot()
        inodes = {str(p.relative_to(self.final)): p.stat().st_ino for p in self.final.rglob('*')}
        self.assertEqual(self.publish()['disposition'], 'already-present')
        self.assertEqual(before, self.store_snapshot())
        self.assertEqual(inodes, {str(p.relative_to(self.final)): p.stat().st_ino for p in self.final.rglob('*')})
        self.assert_closed()

    def test_changed_protected_startup_binds_new_candidate_without_replacing_old(self):
        self.publish(); before = self.store_snapshot(self.final)
        path = self.root / 'etc/mk8.email/gateway.json'; value = json.loads(path.read_bytes())
        value['Admin']['SessionMinutes'] = 45; raw = encoded(value); path.write_bytes(raw)
        self.documents['mk8.email']['configuration']['gateway.json'] = hashlib.sha256(raw).hexdigest()
        self.seal('mk8.email'); result = self.publish()
        self.assertNotEqual(result['publication_sha256'], self.digest)
        self.assertEqual(before, self.store_snapshot(self.final)); self.assert_closed()

    def test_missing_complete_service_set_and_late_hash_mismatch_refuse_before_store_io(self):
        candidate = self.n['application_bundle'](self.data, self.n['bundle']); original = self.n['application_bundle']
        for kind in ('missing', 'order', 'late-hash', 'mode', 'extra'):
            with self.subTest(kind=kind):
                result = copy.deepcopy(candidate)
                if kind == 'missing': result['files'].pop()
                elif kind == 'order': result['files'].reverse()
                elif kind == 'late-hash': result['files'][-1]['sha256'] = '0' * 64
                elif kind == 'mode': result['files'][0]['mode'] = '0755'
                else: result['files'].append(copy.deepcopy(result['files'][-1]))
                self.n['application_bundle'] = lambda *args: result
                before = self.store_snapshot()
                with self.assertRaises(ValueError): self.publish()
                self.assertEqual(before, self.store_snapshot())
        self.n['application_bundle'] = original; self.assert_closed()

    def test_wrong_helper_identity_boolean_length_or_hash_refuse_without_publication(self):
        candidate = self.n['application_bundle'](self.data, self.n['bundle']); original = self.n['application_bundle']
        for field, value in (('file', 'usr/libexec/foreign.py'), ('bytes', True), ('sha256', '0' * 64)):
            with self.subTest(field=field):
                result = copy.deepcopy(candidate); result['dns_credential_helper'][field] = value
                self.n['application_bundle'] = lambda *args: result
                with self.assertRaises(ValueError): self.publish()
                self.assertEqual(self.store_snapshot(), {})
        self.n['application_bundle'] = original; self.assert_closed()

    def test_aggregate_bound_refuses_before_lock_or_pending_creation(self):
        self.n['APP_PUB_LIMIT'] = 1
        with self.assertRaisesRegex(ValueError, 'complete application publication bound'): self.publish()
        self.assertEqual(self.store_snapshot(), {}); self.assert_closed()

    def test_stale_candidate_cannot_replace_fresh_missing_nested_input(self):
        (self.root / 'etc/mk8.email/gateway/database-password.txt').unlink()
        with self.assertRaises(OSError): self.publish()
        self.assertEqual(self.store_snapshot(), {}); self.assert_closed()

    def test_owned_partial_unit_prefix_recovers_only_after_complete_marker_admission(self):
        self.scratch(); folder = self.pending / 'systemd'; folder.mkdir(mode=0o700)
        name = 'systemd/mk8-email-gateway.service'; path = self.pending / name
        path.write_bytes(self.contents[name][:23]); path.chmod(0o600)
        self.assertEqual(self.publish()['disposition'], 'recovered')
        self.assertEqual((self.final / name).read_bytes(), self.contents[name]); self.assert_closed()

    def test_late_foreign_helper_prevents_any_partial_unit_retirement(self):
        self.scratch()
        for folder in self.n['APP_PUB_DIRECTORIES']: (self.pending / folder).mkdir(mode=0o700)
        path = self.pending / 'systemd/mk8-sava-application.service'
        path.write_bytes(self.contents['systemd/mk8-sava-application.service'][:17]); path.chmod(0o600)
        foreign = self.pending / 'helpers/dns-credentials.py'; foreign.write_bytes(b'foreign'); foreign.chmod(0o400)
        before = self.store_snapshot(self.pending)
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(before, self.store_snapshot(self.pending)); self.assert_closed()

    def test_five_file_ownership_record_is_not_adopted_as_application_record(self):
        lock = self.store / '.publisher.lock'; lock.write_bytes(self.n['APP_PUB_LOCK']); lock.chmod(0o400)
        self.pending.mkdir(mode=0o700)
        _, old = self.n['publication_plan'](self.data, self.n['bundle'])
        path = self.pending / 'publication.json'; path.write_bytes(old['publication.json']); path.chmod(0o400)
        before = self.store_snapshot()
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(before, self.store_snapshot()); self.assert_closed()

    def test_foreign_systemd_or_helper_entries_refuse_without_cleanup(self):
        lock = self.store / '.publisher.lock'; lock.write_bytes(self.n['APP_PUB_LOCK']); lock.chmod(0o400)
        for folder in self.n['APP_PUB_DIRECTORIES']:
            with self.subTest(folder=folder):
                self.scratch(); child = self.pending / folder; child.mkdir(mode=0o700)
                path = child / 'foreign'; path.write_bytes(b'preserve'); before = self.store_snapshot()
                with self.assertRaises(ValueError): self.publish()
                self.assertEqual(before, self.store_snapshot())
                path.unlink(); child.rmdir(); (self.pending / 'publication.json').unlink(); self.pending.rmdir()
        self.assert_closed()

    def test_failed_rename_retains_complete_pending_for_checked_recovery(self):
        original = self.n['publication_rename']; self.n['publication_rename'] = Mock(side_effect=OSError('model rename refusal'))
        with self.assertRaises(OSError): self.publish()
        self.assertEqual(set(self.store_snapshot(self.pending)), set(self.contents))
        self.n['publication_rename'] = original
        self.assertEqual(self.publish()['disposition'], 'recovered'); self.assert_closed()

    def test_postrename_fsync_failure_withholds_result_but_retry_verifies_full_tree(self):
        original = self.n['publication_rename']
        def renamed(*args):
            original(*args); self.delivery.fsync = Mock(side_effect=OSError('model postrename fsync'))
        self.n['publication_rename'] = renamed
        with self.assertRaises(OSError): self.publish()
        self.assertTrue(self.final.is_dir()); self.assertFalse(self.pending.exists()); self.assert_closed()
        del self.delivery.fsync
        self.assertEqual(self.publish()['disposition'], 'already-present'); self.assert_closed()

    def test_checked_store_close_failure_withholds_success_even_after_complete_rename(self):
        original = self.delivery.close
        def close(fd):
            inode = os.fstat(fd).st_ino; original(fd)
            if inode == self.store.stat().st_ino: raise OSError('model checked store close')
        self.delivery.close = close
        with self.assertRaises(OSError): self.publish()
        self.assertTrue(self.final.is_dir()); self.assert_closed()

    def test_busy_cooperative_lock_refuses_without_pending_or_payload_mutation(self):
        path = self.store / '.publisher.lock'; path.write_bytes(self.n['APP_PUB_LOCK']); path.chmod(0o400)
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); before = self.store_snapshot()
            with self.assertRaises(BlockingIOError): self.publish()
            self.assertEqual(before, self.store_snapshot()); self.assertFalse(self.pending.exists())
        finally: os.close(fd)
        self.assert_closed()

    def test_missing_store_refuses_without_creating_host_ancestry(self):
        self.store.rmdir()
        with self.assertRaises(FileNotFoundError): self.publish()
        self.assertFalse(self.store.exists()); self.assert_closed()

    def test_main_rejects_manifest_in_either_inactive_store_before_reading(self):
        self.n['dep_resource'] = type('NoLimits', (), {'RLIMIT_CPU': 0, 'RLIMIT_AS': 1, 'RLIMIT_CORE': 2,
                                                      'setrlimit': staticmethod(lambda *args: None)})
        self.n['deployment_read'] = Mock(side_effect=AssertionError('must not read'))
        for store in (self.n['PUB_STORE'], self.n['APP_PUB_STORE']):
            self.n['dep_sys'] = type('Args', (), {'argv': ['-', store + '/manifest.json'], 'stderr': sys.stderr})
            self.assertEqual(self.n['application_publication_main'](self.n['bundle']), 75)
        self.n['deployment_read'].assert_not_called()

    def test_explicit_cli_wrong_arity_refuses_before_any_action(self):
        script = str(ROOT / 'azurelinux3s4.sh')
        for args in (('--publish-application-candidate',), ('--publish-application-candidate', '/manifest.json', 'extra')):
            result = subprocess.run(['bash', script, *args], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 64); self.assertEqual(result.stdout, b'')
        program = emitted_program()
        self.assertIn((ROOT / 'Deployment/application_publication.py').read_text(), program)
        self.assertIn('raise SystemExit(application_publication_main(bundle))', program)

    def test_whole_shipped_private_publication_retains_complete_bundle_no_activation(self):
        result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['stored_files'], 13)
        self.assertEqual(receipt['publication_sha256'], self.digest)
        self.assertTrue(all(value is False for value in receipt['authority'].values()))
        self.assertEqual(set(self.store_snapshot(self.final)), set(self.contents))
        self.assertFalse((self.root / 'etc/systemd').exists())
        self.assertFalse((self.root / 'usr').exists())

    def test_whole_shipped_postrename_refusal_retains_complete_bytes_but_no_json(self):
        result = self.run_emitted('postrename')
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Inactive application candidate publication refused\n')
        self.assertTrue(self.final.is_dir()); self.assertFalse(self.pending.exists())
        self.assertEqual(set(self.store_snapshot(self.final)), set(self.contents))

    def test_whole_shipped_late_reference_refusal_precedes_store_mutation(self):
        path = self.root / 'etc/mk8.email/gateway.json'; value = json.loads(path.read_bytes())
        value['Database']['PasswordFile'] = '/run/credentials/mk8-email-worker.service/database-password.txt'
        raw = encoded(value); path.write_bytes(raw)
        self.documents['mk8.email']['configuration']['gateway.json'] = hashlib.sha256(raw).hexdigest(); self.seal('mk8.email')
        result = self.run_emitted()
        self.assertEqual(result.returncode, 75, result.stderr); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Inactive application candidate publication refused\n')
        self.assertEqual(self.store_snapshot(), {})

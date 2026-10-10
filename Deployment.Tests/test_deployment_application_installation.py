"""Private root delivery of the disconnected fixed application-file installer."""

import collections
import copy
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
from unittest.mock import Mock

from test_deployment_policy import emitted_program, encoded
from test_deployment_publication import PublicationOS
from test_deployment_releases import ROOT, ReleaseFixture


class ApplicationInstallationTests(ReleaseFixture):
    def setUp(self):
        super().setUp()
        for name in ('Deployment/publication.py', 'Deployment/application_publication.py',
                     'Deployment/application_installation.py'):
            exec(compile((ROOT / name).read_bytes(), name, 'exec'), self.n)
        self.delivery = PublicationOS(self.root); self.n['dep_os'] = self.delivery
        self.state = self.root / self.n['APP_INSTALL_STATE'][1:]
        self.units = self.root / self.n['APP_INSTALL_UNITS'][1:]
        self.helpers = self.root / self.n['APP_INSTALL_HELPERS'][1:]
        for path in (self.state, self.units, self.helpers):
            path.mkdir(parents=True, mode=0o700)
            for parent in path.parents:
                if parent == self.root.parent: break
                parent.chmod(0o700)
        self.data = encoded(self.value)
        self.digest, self.record, self.rows = self.n['application_installation_plan'](self.data, self.n['bundle'])
        self.capture = None

    def install(self):
        return self.n['application_installation'](encoded(self.value), self.n['bundle'])

    def destinations(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                for base in (self.state, self.units, self.helpers) for path in base.rglob('*')
                if path.is_file() and not path.is_symlink()}

    def source_snapshot(self):
        return {name: row for name, row in self.snapshot().items()
                if not (name.startswith('var/') or name.startswith('etc/systemd/') or name.startswith('usr/'))}

    def assert_closed(self):
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def own(self):
        (self.state / 'installation.json').write_bytes(self.record)
        (self.state / 'installation.json').chmod(0o400)

    def leaf(self, row=None):
        row = self.rows[0] if row is None else row
        return self.root / row['parent'][1:] / row['leaf']

    def refused(self, message='.'):
        before = self.destinations()
        with self.assertRaisesRegex((ValueError, OSError), message): self.install()
        self.assertEqual(before, self.destinations()); self.assert_closed()

    def run_delivered(self, fault=False):
        self.manifest_file.write_bytes(encoded(self.value))
        original = emitted_program(); body, dispatch = original.split('action = sys.argv[1]\n', 1)
        seam = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                '_install_original_os = dep_os\n'
                '_install_private_root = ' + repr(str(self.root)) + '\n'
                'class _InstallationPrivateOS:\n'
                '    def __getattr__(self, name): return getattr(_install_original_os, name)\n'
                '    def open(self, path, flags, *args, **kwargs):\n'
                '        return _install_original_os.open(_install_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                'dep_os = _InstallationPrivateOS()\n')
        if fault:
            seam += ('_install_original_write = dep_os.write\n'
                     'def _install_zero_payload(fd, raw):\n'
                     '    return 0 if raw.startswith(b"# Inactive candidate;") else _install_original_write(fd, raw)\n'
                     'dep_os.write = _install_zero_payload\n')
        trampoline = ('try:\n'
                      '    result = application_installation(deployment_read("/manifest.json"), bundle)\n'
                      'except (OSError, ValueError):\n'
                      '    print("Private application installation model refused", file=dep_sys.stderr)\n'
                      '    raise SystemExit(75)\n'
                      'print(publication_encoded(result).decode("ascii"), end="")\n')
        code = body + seam + trampoline
        before = self.source_snapshot()
        result = subprocess.run([sys.executable, '-I', '-'], input=code.encode('ascii'),
                                capture_output=True, timeout=45, check=False)
        self.assertEqual(before, self.source_snapshot())
        self.capture = {'program': code, 'original_dispatch': 'action = sys.argv[1]\n' + dispatch,
                        'private_seam': seam, 'private_trampoline': trampoline,
                        'original_program_sha256': hashlib.sha256(original.encode('ascii')).hexdigest(),
                        'input': self.manifest_file.read_bytes().decode('ascii'),
                        'stdout': result.stdout.decode('ascii'), 'stderr': result.stderr.decode('ascii'),
                        'wait': result.returncode, 'explicit_zero_payload_fault': fault}
        return result

    def test_complete_single_family_files_modes_and_ownership_record_before_success(self):
        before = self.source_snapshot(); result = self.install()
        self.assertEqual(result['files'], 10); self.assertEqual(result['changed_files'], 10)
        self.assertEqual(result['publication_sha256'], self.digest)
        self.assertEqual(result['installation_record_sha256'], hashlib.sha256(self.record).hexdigest())
        self.assertTrue(result['checked_closes_completed']); self.assertTrue(result['file_and_directory_fsync_returned'])
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertEqual(stat.S_IMODE((self.state / 'installation.json').stat().st_mode), 0o400)
        for row in self.rows:
            self.assertEqual(self.leaf(row).read_bytes(), row['raw'])
            self.assertEqual(stat.S_IMODE(self.leaf(row).stat().st_mode), row['mode'])
        self.assertEqual(before, self.source_snapshot()); self.assert_closed()

    def test_dual_family_installs_both_complete_gateway_units(self):
        self.value['public']['ipv6'] = '2001:4860::20'
        result = self.install(); self.assertEqual(result['files'], 11)
        for family in (4, 6): self.assertTrue((self.units / ('mk8-dns-gateway' + str(family) + '.service')).is_file())
        self.assert_closed()

    def test_ipv6_only_installs_no_ipv4_gateway(self):
        self.value['public'].update(ipv4=None, ipv6='2001:4860::20')
        self.assertEqual(self.install()['files'], 10)
        self.assertTrue((self.units / 'mk8-dns-gateway6.service').is_file())
        self.assertFalse((self.units / 'mk8-dns-gateway4.service').exists()); self.assert_closed()

    def test_idempotent_complete_retry_preserves_inodes_bytes_and_mtimes(self):
        self.install(); before = self.destinations()
        identities = {name: self.root.joinpath(name).stat() for name in before}
        self.assertEqual(self.install()['changed_files'], 0); self.assertEqual(before, self.destinations())
        for name, previous in identities.items():
            current = self.root.joinpath(name).stat()
            self.assertEqual((current.st_ino, current.st_mtime_ns, current.st_ctime_ns),
                             (previous.st_ino, previous.st_mtime_ns, previous.st_ctime_ns))
        self.assert_closed()

    def test_all_authorities_false_and_no_activation_command_or_default_dispatch(self):
        result = self.install(); self.assertEqual(len(result['authority']), 16)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        emitter = (ROOT / 'SSH/policy.sh.in').read_text(); dispatch = emitter.split('action = sys.argv[1]\n', 1)[1]
        self.assertNotIn('application_installation(', dispatch)
        self.assertNotIn('application_installation', (ROOT / 'Bootstrap/main.sh').read_text())
        self.assertEqual(self.n['APP_INSTALL_STATE'], '/var/lib/azurelinux3s4/application-installation')
        self.assert_closed()

    def test_matching_unowned_existing_unit_refuses_before_lock_or_record_writes(self):
        path = self.leaf(); path.write_bytes(self.rows[0]['raw']); path.chmod(0o644)
        self.refused('lacks exact installation ownership'); self.assertEqual(set(self.state.iterdir()), set())

    def test_late_foreign_helper_refuses_before_any_earlier_unit_or_state_write(self):
        path = self.leaf(self.rows[-1]); path.write_bytes(b'foreign helper'); path.chmod(0o755)
        self.refused('lacks exact installation ownership'); self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(list(self.state.iterdir()), [])

    def test_owned_prefix_completion_preserves_inode_and_never_unlinks(self):
        self.own(); path = self.leaf(); path.write_bytes(self.rows[0]['raw'][:31]); path.chmod(0o600)
        inode = path.stat().st_ino; self.delivery.unlink = Mock(side_effect=AssertionError('unlink forbidden'))
        self.assertEqual(self.install()['changed_files'], 10)
        self.assertEqual(path.stat().st_ino, inode); self.assertEqual(path.read_bytes(), self.rows[0]['raw'])
        self.delivery.unlink.assert_not_called(); self.assert_closed()

    def test_late_owned_foreign_content_withholds_completion_of_earlier_prefix(self):
        self.own(); first = self.leaf(); first.write_bytes(self.rows[0]['raw'][:19]); first.chmod(0o600)
        late = self.leaf(self.rows[-1]); late.write_bytes(b'foreign'); late.chmod(0o600)
        self.refused('prefix/content mismatch'); self.assertEqual(first.read_bytes(), self.rows[0]['raw'][:19])
        self.assertFalse((self.state / '.installer.lock').exists())

    def test_partial_final_mode_payload_refuses_even_with_exact_ownership(self):
        self.own(); path = self.leaf(); path.write_bytes(self.rows[0]['raw'][:19]); path.chmod(0o644)
        self.refused('prefix/content mismatch')

    def test_partial_or_wrong_ownership_record_never_adopts_existing_prefix(self):
        for raw in (self.record[:33], b'foreign\n'):
            path = self.state / 'installation.json'
            if path.exists(): path.chmod(0o600)
            path.write_bytes(raw); path.chmod(0o400)
            self.refused('publication bytes mismatch')
        self.assertEqual(list(self.units.iterdir()), [])

    def test_changed_manifest_after_installation_refuses_and_preserves_all_files(self):
        self.install(); self.value['public']['ipv4'] = '8.8.4.4'
        self.refused('publication bytes mismatch')

    def test_foreign_extra_state_entry_is_not_removed_or_adopted(self):
        marker = self.state / 'foreign'; marker.write_bytes(b'preserve')
        self.refused('foreign installation-state'); self.assertEqual(marker.read_bytes(), b'preserve')

    def test_symlink_destination_and_hardlink_destination_refuse(self):
        self.own(); path = self.leaf(); foreign = self.units / 'foreign'; foreign.write_bytes(self.rows[0]['raw']); foreign.chmod(0o644)
        path.symlink_to(foreign); self.refused('unqualified owned'); path.unlink()
        os.link(foreign, path); self.refused('unqualified owned')

    def test_symlink_ancestry_and_group_writable_destination_refuse(self):
        self.units.chmod(0o770); self.refused('unprotected'); self.units.chmod(0o700)
        original = self.units.parent / 'original'; self.units.rename(original); self.units.symlink_to(original)
        self.refused('unprotected'); self.units.unlink(); original.rename(self.units)

    def test_missing_preexisting_target_ancestry_is_not_created(self):
        self.helpers.rmdir(); self.refused(); self.assertFalse(self.helpers.exists())

    def test_cooperative_lock_contention_refuses_without_file_installation(self):
        path = self.state / '.installer.lock'; path.write_bytes(self.n['APP_INSTALL_LOCK']); path.chmod(0o400)
        with path.open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.refused(); self.assertEqual(list(self.units.iterdir()), [])

    def test_short_writes_complete_every_original_payload(self):
        real = os.write; self.delivery.write = lambda fd, raw: real(fd, raw[:13])
        self.test_complete_single_family_files_modes_and_ownership_record_before_success()

    def test_zero_payload_write_refuses_then_exact_prefix_retry_completes(self):
        real = os.write
        self.delivery.write = lambda fd, raw: 0 if raw == self.rows[0]['raw'] else real(fd, raw)
        with self.assertRaisesRegex(ValueError, 'incomplete installation write'): self.install()
        path = self.leaf(); self.assertEqual(path.read_bytes(), b''); self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        del self.delivery.write
        self.assertEqual(self.install()['changed_files'], 10); self.assert_closed()

    def test_partial_ownership_write_cannot_publish_success_or_be_recovered(self):
        real = os.write
        def write(fd, raw):
            if raw == self.record: return real(fd, raw[:17])
            if raw == self.record[17:]: return 0
            return real(fd, raw)
        self.delivery.write = write
        with self.assertRaisesRegex(ValueError, 'incomplete publication write'): self.install()
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record[:17])
        del self.delivery.write; self.refused('unqualified publication leaf')
        self.assertEqual(list(self.units.iterdir()), [])

    def test_checked_close_failure_after_file_write_withholds_receipt(self):
        real = self.delivery.close; armed = True
        def close(fd):
            nonlocal armed
            target = os.readlink('/proc/self/fd/' + str(fd))
            real(fd)
            if armed and target == str(self.leaf()):
                armed = False; raise OSError('explicit checked close failure')
        self.delivery.close = close
        with self.assertRaisesRegex(OSError, 'checked close failure'): self.install()
        self.assertTrue(self.leaf().exists()); self.assert_closed()
        del self.delivery.close; self.assertEqual(self.install()['changed_files'], 9)

    def test_fsync_failure_can_leave_complete_bytes_without_success(self):
        real = os.fsync; armed = True
        def sync(fd):
            nonlocal armed
            if armed and os.readlink('/proc/self/fd/' + str(fd)) == str(self.leaf()):
                armed = False; raise OSError('explicit sync failure')
            return real(fd)
        self.delivery.fsync = sync
        with self.assertRaisesRegex(OSError, 'sync failure'): self.install()
        self.assertEqual(self.leaf().read_bytes(), self.rows[0]['raw']); self.assert_closed()
        del self.delivery.fsync; self.assertEqual(self.install()['changed_files'], 9)

    def test_missing_raw_source_refuses_before_installation_directory_io(self):
        (self.root / 'etc/mk8.email/gateway/database-password.txt').unlink()
        entry = self.n['installation_directories']; self.n['installation_directories'] = Mock(side_effect=AssertionError('target IO forbidden'))
        try:
            with self.assertRaises(OSError): self.install()
            self.n['installation_directories'].assert_not_called(); self.assertEqual(self.destinations(), {})
        finally: self.n['installation_directories'] = entry

    def test_corrupt_late_fresh_payload_commitment_refuses_before_target_io(self):
        original = self.n['application_publication_plan']; digest, contents = original(self.data, self.n['bundle'])
        value = copy.deepcopy(contents); intent = json.loads(value['publication.json']); intent['files'][-1]['sha256'] = '0' * 64
        value['publication.json'] = encoded(intent)
        self.n['application_publication_plan'] = lambda *args: (digest, value)
        entry = self.n['installation_directories']; self.n['installation_directories'] = Mock(side_effect=AssertionError('target IO forbidden'))
        try:
            with self.assertRaisesRegex(ValueError, 'commitment mismatch'): self.install()
            self.n['installation_directories'].assert_not_called()
        finally: self.n['application_publication_plan'] = original; self.n['installation_directories'] = entry

    def test_replaced_held_directory_path_refuses_before_write(self):
        original = self.n['installation_context']; calls = 0
        def context(held, links):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.helpers.rename(self.helpers.parent / 'previous'); self.helpers.mkdir(mode=0o700)
            return original(held, links)
        self.n['installation_context'] = context
        with self.assertRaisesRegex(ValueError, 'installation (held ancestry|directory path) changed'): self.install()
        self.assertEqual(list(self.units.iterdir()), []); self.assert_closed()

    def test_whole_delivered_library_positive_private_trampoline_binds_files(self):
        result = self.run_delivered(); self.assertEqual(result.returncode, 0, result.stderr.decode())
        output = json.loads(result.stdout); self.assertEqual(output['files'], 10)
        self.assertEqual(output['publication_sha256'], self.digest)
        self.assertTrue(all(value is False for value in output['authority'].values()))
        for row in self.rows:
            self.assertEqual(self.leaf(row).read_bytes(), row['raw'])
            self.assertEqual(stat.S_IMODE(self.leaf(row).stat().st_mode), row['mode'])

    def test_whole_delivered_library_zero_write_is_model75_not_cli_activation(self):
        result = self.run_delivered(True)
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Private application installation model refused\n')
        self.assertEqual(self.leaf().read_bytes(), b'')
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)

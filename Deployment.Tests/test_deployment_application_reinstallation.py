"""Private owned-file reinstallation and explicit interrupted-transition models."""

import deployment_fixture as net_fixture

import collections
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from test_deployment_policy import emitted_program, encoded
from test_deployment_publication import PublicationOS
from test_deployment_releases import ROOT, ReleaseFixture
import test_deployment_application_installation as installation_fixture


class ApplicationReinstallationTests(ReleaseFixture):
    install = installation_fixture.ApplicationInstallationTests.install
    destinations = installation_fixture.ApplicationInstallationTests.destinations
    source_snapshot = installation_fixture.ApplicationInstallationTests.source_snapshot
    assert_closed = installation_fixture.ApplicationInstallationTests.assert_closed
    leaf = installation_fixture.ApplicationInstallationTests.leaf

    def setUp(self):
        super().setUp()
        for name in ('Deployment/publication.py', 'Deployment/application_publication.py',
                     'Deployment/application_installation.py', 'Deployment/application_rollback.py',
                     'Deployment/application_reinstallation.py'):
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
        self.digest, self.record, self.rows, self.marker = self.n['application_rollback_plan'](encoded(self.value), self.n['bundle'])
        self.capture = None

    def rollback(self):
        return self.n['application_rollback'](encoded(self.value), self.n['bundle'])

    def reinstall(self):
        return self.n['application_reinstallation'](encoded(self.value), self.n['bundle'])

    def completed(self):
        self.install(); self.rollback()
        self.assertEqual({p.name for p in self.state.iterdir()}, {'.installer.lock', 'rollback.json'})
        self.assertEqual(list(self.units.iterdir()), []); self.assertEqual(list(self.helpers.iterdir()), [])

    def refused(self, message='.'):
        before = self.destinations()
        with self.assertRaisesRegex((OSError, ValueError), message): self.reinstall()
        self.assertEqual(self.destinations(), before); self.assert_closed()

    def late_flock(self, callback):
        def locked(fd, operation):
            fcntl.flock(fd, operation); callback()
        self.n['pub_fcntl'] = SimpleNamespace(LOCK_EX=fcntl.LOCK_EX, LOCK_NB=fcntl.LOCK_NB, flock=locked)

    def run_delivered(self, fault=False):
        self.completed(); self.manifest_file.write_bytes(encoded(self.value))
        original = emitted_program(); body, dispatch = original.split('action = sys.argv[1]\n', 1)
        seam = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                '_reinstall_original_os = dep_os\n'
                '_reinstall_private_root = ' + repr(str(self.root)) + '\n'
                'class _ReinstallationPrivateOS:\n'
                '    def __getattr__(self, name): return getattr(_reinstall_original_os, name)\n'
                '    def open(self, path, flags, *args, **kwargs):\n'
                '        return _reinstall_original_os.open(_reinstall_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                'dep_os = _ReinstallationPrivateOS()\n')
        if fault:
            seam += ('def _reinstall_zero_owner(fd, raw): return 0\n'
                     'dep_os.write = _reinstall_zero_owner\n')
        trampoline = ('try:\n'
                      '    result = application_reinstallation(deployment_read("/manifest.json"), bundle)\n'
                      'except (OSError, ValueError):\n'
                      '    print("Private application reinstallation model refused", file=dep_sys.stderr)\n'
                      '    raise SystemExit(75)\n'
                      'print(publication_encoded(result).decode("ascii"), end="")\n')
        code = body + seam + trampoline; before = self.source_snapshot()
        before_destinations = self.destinations()
        result = subprocess.run([sys.executable, '-I', '-'], input=code.encode('ascii'),
                                capture_output=True, timeout=45, check=False)
        self.assertEqual(before, self.source_snapshot())
        self.capture = {'program': code, 'original_dispatch': 'action = sys.argv[1]\n' + dispatch,
                        'private_seam': seam, 'private_trampoline': trampoline,
                        'original_program_sha256': hashlib.sha256(original.encode('ascii')).hexdigest(),
                        'input': self.manifest_file.read_bytes().decode('ascii'),
                        'stdout': result.stdout.decode('ascii'), 'stderr': result.stderr.decode('ascii'),
                        'wait': result.returncode, 'explicit_zero_ownership_write_fault': fault,
                        'before_destination_files': {name: {'bytes': len(row[0]), 'sha256': hashlib.sha256(row[0]).hexdigest(),
                                                          'mode': format(row[1], '04o')} for name, row in before_destinations.items()}}
        return result

    def test_complete_rollback_to_reinstallation_binds_every_file_and_source(self):
        self.completed(); before = self.source_snapshot()
        with self.assertRaisesRegex(ValueError, 'foreign installation-state'): self.install()
        result = self.reinstall()
        self.assertEqual(result['disposition'], 'rollback-marker-retired'); self.assertTrue(result['rollback_marker_observed'])
        self.assertEqual(result['publication_sha256'], self.digest)
        self.assertEqual(result['installation']['changed_files'], 10)
        self.assertEqual(result['installation']['installation_record_sha256'], hashlib.sha256(self.record).hexdigest())
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertFalse((self.state / 'rollback.json').exists())
        for row in self.rows:
            self.assertEqual(self.leaf(row).read_bytes(), row['raw'])
            self.assertEqual(stat.S_IMODE(self.leaf(row).stat().st_mode), row['mode'])
        self.assertEqual(before, self.source_snapshot()); self.assert_closed()

    def test_dual_family_reinstalls_both_gateway_files(self):
        self.value['public']['ipv6'] = net_fixture.PUBLIC6; self.completed()
        result = self.reinstall(); self.assertEqual(result['installation']['files'], 11)
        for family in (4, 6): self.assertTrue((self.units / ('mk8-dns-gateway' + str(family) + '.service')).is_file())
        self.assert_closed()

    def test_ipv6_only_reinstallation_retains_its_exact_family_set(self):
        self.value['public'].update(ipv4=None, ipv6=net_fixture.PUBLIC6); self.completed()
        self.assertEqual(self.reinstall()['installation']['files'], 10)
        self.assertTrue((self.units / 'mk8-dns-gateway6.service').is_file())
        self.assertFalse((self.units / 'mk8-dns-gateway4.service').exists()); self.assert_closed()

    def test_complete_retry_preserves_inodes_times_and_honest_marker_observation(self):
        self.completed(); self.reinstall(); before = self.destinations()
        identities = {name: (self.root / name).stat() for name in before}
        result = self.reinstall(); self.assertFalse(result['rollback_marker_observed'])
        self.assertEqual(result['disposition'], 'owned-installation-resumed')
        self.assertEqual(result['installation']['changed_files'], 0); self.assertEqual(self.destinations(), before)
        for name, old in identities.items():
            current = (self.root / name).stat()
            self.assertEqual((current.st_ino, current.st_mtime_ns, current.st_ctime_ns),
                             (old.st_ino, old.st_mtime_ns, old.st_ctime_ns))
        self.assert_closed()

    def test_no_owner_no_marker_cannot_turn_transition_into_first_install(self):
        self.refused('exact rollback or installation ownership|No such file'); self.assertEqual(list(self.state.iterdir()), [])

    def test_remaining_owned_payload_refuses_incomplete_rollback_without_mutation(self):
        self.install(); path = self.state / 'rollback.json'; path.write_bytes(self.marker); path.chmod(0o400)
        self.refused('unexpectedly present'); self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)

    def test_retained_marker_and_owned600_prefix_refuse_before_completion(self):
        self.completed(); path = self.state / 'installation.json'; path.write_bytes(self.record); path.chmod(0o400)
        first = self.leaf(); first.write_bytes(self.rows[0]['raw'][:31]); first.chmod(0o600)
        self.refused('unexpectedly present'); self.assertEqual(first.read_bytes(), self.rows[0]['raw'][:31])

    def test_late_foreign_payload_blocks_ownership_creation_and_marker_retirement(self):
        self.completed(); path = self.leaf(self.rows[-1]); path.write_bytes(b'foreign'); path.chmod(0o755)
        self.refused('unexpectedly present'); self.assertFalse((self.state / 'installation.json').exists())

    def test_partial_or_foreign_marker_is_not_adopted(self):
        self.completed(); path = self.state / 'rollback.json'
        for raw in (self.marker[:41], b'foreign\n'):
            path.chmod(0o600); path.write_bytes(raw); path.chmod(0o400)
            self.refused('publication bytes mismatch')
        self.assertFalse((self.state / 'installation.json').exists())

    def test_partial_or_foreign_owner_preserves_complete_marker(self):
        self.completed(); path = self.state / 'installation.json'
        for raw in (self.record[:41], b'foreign\n'):
            if path.exists(): path.chmod(0o600)
            path.write_bytes(raw); path.chmod(0o400); self.refused('publication bytes mismatch')
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)

    def test_marker_symlink_or_hardlink_refuses_without_touching_alias(self):
        self.completed(); path = self.state / 'rollback.json'; path.unlink()
        alias = self.root / 'other-owner'; alias.write_bytes(self.marker); alias.chmod(0o400)
        path.symlink_to(alias); self.refused('unqualified publication'); path.unlink()
        os.link(alias, path); self.refused('unqualified publication')
        self.assertEqual(alias.read_bytes(), self.marker); self.assertEqual(alias.stat().st_nlink, 2)

    def test_owner_hardlink_refuses_before_marker_retirement(self):
        self.completed(); alias = self.root / 'other-owner'; alias.write_bytes(self.record); alias.chmod(0o400)
        os.link(alias, self.state / 'installation.json'); self.refused('unqualified publication')
        self.assertEqual(alias.stat().st_nlink, 2)

    def test_late_symlink_destination_is_never_followed(self):
        self.completed(); foreign = self.root / 'foreign'; foreign.write_bytes(b'preserve')
        self.leaf(self.rows[-1]).symlink_to(foreign); self.refused('unexpectedly present')
        self.assertEqual(foreign.read_bytes(), b'preserve')

    def test_foreign_state_entry_refuses_without_cleanup(self):
        self.completed(); path = self.state / 'foreign'; path.write_bytes(b'preserve')
        self.refused('foreign reinstallation-state'); self.assertEqual(path.read_bytes(), b'preserve')

    def test_changed_manifest_cannot_reuse_previous_marker_or_owner(self):
        self.completed(); self.value['public']['ipv4'] = net_fixture.OTHER_PUBLIC4
        self.refused('publication bytes mismatch'); self.assertFalse((self.state / 'installation.json').exists())

    def test_missing_original_source_refuses_before_destination_open(self):
        self.completed(); (self.root / 'etc/mk8.drava/ipc-token.txt').unlink()
        opened = Mock(side_effect=AssertionError('destination IO forbidden before fresh source admission'))
        self.n['installation_directories'] = opened
        with self.assertRaises((OSError, ValueError)): self.reinstall()
        opened.assert_not_called(); self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.assert_closed()

    def test_lock_contention_refuses_before_ownership_creation(self):
        self.completed()
        with (self.state / '.installer.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); self.refused()
        self.assertFalse((self.state / 'installation.json').exists())

    def test_late_foreign_state_under_lock_is_not_removed(self):
        self.completed(); path = self.state / 'foreign'
        self.late_flock(lambda: path.write_bytes(b'late'))
        with self.assertRaisesRegex(ValueError, 'foreign reinstallation-state'): self.reinstall()
        self.assertEqual(path.read_bytes(), b'late'); self.assertFalse((self.state / 'installation.json').exists())
        self.assertEqual(list(self.units.iterdir()), []); self.assert_closed()

    def test_late_marker_replacement_under_lock_refuses_exact_identity_drift(self):
        self.completed(); path = self.state / 'rollback.json'
        def replace():
            path.unlink(); path.write_bytes(self.marker); path.chmod(0o400)
        self.late_flock(replace)
        with self.assertRaisesRegex(ValueError, 'records changed before lock'): self.reinstall()
        self.assertFalse((self.state / 'installation.json').exists()); self.assert_closed()

    def test_target_parent_sync_failure_preserves_marker_without_new_owner(self):
        self.completed(); real = os.fsync
        def sync(fd):
            if os.fstat(fd).st_ino == self.units.stat().st_ino: raise OSError('target-parent sync fault')
            real(fd)
        self.delivery.fsync = sync; self.refused('target-parent sync fault')
        self.assertFalse((self.state / 'installation.json').exists())

    def test_partial_owner_write_refuses_retry_without_retiring_marker(self):
        self.completed(); real = os.write; calls = 0
        def write(fd, raw):
            nonlocal calls
            calls += 1
            return real(fd, raw[:19]) if calls == 1 else 0
        self.delivery.write = write
        with self.assertRaisesRegex(ValueError, 'incomplete publication write'): self.reinstall()
        path = self.state / 'installation.json'; self.assertEqual(path.read_bytes(), self.record[:19])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.delivery.write = real; self.refused('unqualified publication'); self.assert_closed()

    def test_owner_sync_failure_retains_both_records_then_exact_retry_completes(self):
        self.completed(); original = self.n['reinstallation_owner_sync']
        self.n['reinstallation_owner_sync'] = Mock(side_effect=OSError('owner synchronization fault'))
        with self.assertRaisesRegex(OSError, 'owner synchronization fault'): self.reinstall()
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.assertEqual(list(self.units.iterdir()), [])
        self.n['reinstallation_owner_sync'] = original
        self.assertEqual(self.reinstall()['installation']['changed_files'], 10); self.assert_closed()

    def test_marker_unlink_fault_preserves_synchronized_owner_for_retry(self):
        self.completed(); real = os.unlink
        self.delivery.unlink = Mock(side_effect=OSError('marker retirement fault'))
        with self.assertRaisesRegex(OSError, 'marker retirement fault'): self.reinstall()
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.delivery.unlink = real
        self.assertTrue(self.reinstall()['rollback_marker_observed']); self.assert_closed()

    def test_postunlink_parent_sync_fault_leaves_owner_only_and_retry_reinstalls(self):
        self.completed(); real = os.fsync; failed = False
        def sync(fd):
            nonlocal failed
            if not failed and not (self.state / 'rollback.json').exists() and os.fstat(fd).st_ino == self.state.stat().st_ino:
                failed = True; raise OSError('post-unlink parent sync fault')
            real(fd)
        self.delivery.fsync = sync
        with self.assertRaisesRegex(OSError, 'post-unlink parent sync fault'): self.reinstall()
        self.assertTrue(failed); self.assertFalse((self.state / 'rollback.json').exists())
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertEqual(list(self.units.iterdir()), [])
        self.delivery.fsync = real
        result = self.reinstall(); self.assertFalse(result['rollback_marker_observed'])
        self.assertEqual(result['installation']['changed_files'], 10); self.assert_closed()

    def test_zero_payload_after_transition_keeps_empty600_prefix_and_resume_inode(self):
        self.completed(); real = os.write
        self.delivery.write = lambda fd, raw: 0 if raw.startswith(b'# Inactive candidate;') else real(fd, raw)
        with self.assertRaisesRegex(ValueError, 'incomplete installation write'): self.reinstall()
        first = self.leaf(); inode = first.stat().st_ino
        self.assertEqual(first.read_bytes(), b''); self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
        self.assertFalse((self.state / 'rollback.json').exists())
        self.delivery.write = real
        self.assertEqual(self.reinstall()['installation']['changed_files'], 10)
        self.assertEqual(first.stat().st_ino, inode); self.assert_closed()

    def test_interrupted_second_payload_keeps_first_then_resumes_remaining_set(self):
        self.completed(); original = self.n['installation_write']; calls = 0
        def write(parent, row, previous):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('second-payload fault')
            return original(parent, row, previous)
        self.n['installation_write'] = write
        with self.assertRaisesRegex(OSError, 'second-payload fault'): self.reinstall()
        first = self.leaf(); identity = first.stat()
        self.assertEqual(first.read_bytes(), self.rows[0]['raw']); self.assertFalse(self.leaf(self.rows[1]).exists())
        self.n['installation_write'] = original
        self.assertEqual(self.reinstall()['installation']['changed_files'], 9)
        self.assertEqual(first.stat(), identity); self.assert_closed()

    def test_original_source_change_between_transition_and_writer_withholds_payloads(self):
        self.completed(); original = self.n['application_installation']
        def changed(data, producer):
            token = self.root / 'etc/mk8.drava/ipc-token.txt'; token.write_bytes(b'B' * 48 + b'\n')
            return original(data, producer)
        self.n['application_installation'] = changed
        with self.assertRaisesRegex(ValueError, 'publication bytes mismatch'): self.reinstall()
        self.assertFalse((self.state / 'rollback.json').exists())
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertEqual(list(self.units.iterdir()), []); self.assert_closed()

    def test_checked_close_after_marker_retirement_withholds_installer_and_retry_succeeds(self):
        self.completed(); real = self.delivery.close; failed = False
        def close(fd):
            nonlocal failed
            real(fd)
            if not failed and not (self.state / 'rollback.json').exists():
                failed = True; raise OSError('post-retirement checked-close fault')
        self.delivery.close = close
        with self.assertRaisesRegex(OSError, 'post-retirement checked-close fault'): self.reinstall()
        self.assertTrue(failed); self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.delivery.close = real
        self.assertEqual(self.reinstall()['installation']['changed_files'], 10); self.assert_closed()

    def test_unrelated_units_helpers_and_source_bytes_are_preserved(self):
        self.completed(); files = (self.units / 'other-owner.service', self.helpers / 'other-helper')
        for path in files: path.write_bytes(b'foreign owner bytes')
        identities = {str(path): path.stat() for path in files}; before = self.source_snapshot()
        self.reinstall()
        for path in files: self.assertEqual(path.stat(), identities[str(path)]); self.assertEqual(path.read_bytes(), b'foreign owner bytes')
        self.assertEqual(self.source_snapshot(), before); self.assert_closed()

    def test_all_authorities_false_and_actual_dispatcher_and_defaults_remain_disconnected(self):
        self.completed(); result = self.reinstall()
        self.assertEqual(len(result['authority']), 12); self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertTrue(all(value is False for value in result['installation']['authority'].values()))
        self.assertFalse(result['authority']['prior_rollback_proven']); self.assertTrue(result['checked_closes_completed'])
        dispatch = (ROOT / 'SSH/policy.sh.in').read_text().split('action = sys.argv[1]\n', 1)[1]
        self.assertNotIn('application_reinstallation(', dispatch)
        self.assertNotIn('application_reinstallation', (ROOT / 'Bootstrap/main.sh').read_text()); self.assert_closed()

    def test_whole_delivered_library_positive_is_private_model_with_full_file_set(self):
        result = self.run_delivered(); self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout); self.assertEqual(value['installation']['files'], 10)
        self.assertTrue(value['rollback_marker_observed']); self.assertTrue(value['checked_closes_completed'])
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertTrue(all(flag is False for flag in value['installation']['authority'].values()))
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertFalse((self.state / 'rollback.json').exists())
        for row in self.rows: self.assertEqual(self.leaf(row).read_bytes(), row['raw'])
        self.assert_closed()

    def test_whole_delivered_zero_owner_write_is_model75_with_marker_retained(self):
        result = self.run_delivered(fault=True); self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'Private application reinstallation model refused\n')
        path = self.state / 'installation.json'; self.assertEqual(path.read_bytes(), b'')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.assertEqual(list(self.units.iterdir()), []); self.assertEqual(list(self.helpers.iterdir()), [])
        self.assert_closed()

"""Owned first-installation rollback in private filesystems; no manager actions."""

import deployment_fixture as net_fixture

import collections
import hashlib
import json
import os
import stat
import subprocess
import sys
from unittest.mock import Mock

from test_deployment_policy import emitted_program, encoded
from test_deployment_releases import ROOT, ReleaseFixture
from test_deployment_publication import PublicationOS
import test_deployment_application_installation as installation_fixture


class ApplicationRollbackTests(ReleaseFixture):
    install = installation_fixture.ApplicationInstallationTests.install
    destinations = installation_fixture.ApplicationInstallationTests.destinations
    source_snapshot = installation_fixture.ApplicationInstallationTests.source_snapshot
    assert_closed = installation_fixture.ApplicationInstallationTests.assert_closed
    leaf = installation_fixture.ApplicationInstallationTests.leaf
    own = installation_fixture.ApplicationInstallationTests.own

    def setUp(self):
        super().setUp()
        for name in ('Deployment/publication.py', 'Deployment/application_publication.py',
                     'Deployment/application_installation.py', 'Deployment/application_rollback.py'):
            exec(compile((ROOT / name).read_bytes(), name, 'exec'), self.n)
        self.delivery = PublicationOS(self.root); self.n['dep_os'] = self.delivery
        self.state = self.root / self.n['APP_INSTALL_STATE'][1:]
        self.units = self.root / self.n['APP_INSTALL_UNITS'][1:]
        self.helpers = self.root / self.n['APP_INSTALL_HELPERS'][1:]
        self.sysusers = self.root / self.n['APP_INSTALL_SYSUSERS'][1:]
        for path in (self.state, self.units, self.helpers, self.sysusers):
            path.mkdir(parents=True, mode=0o700)
            for parent in path.parents:
                if parent == self.root.parent: break
                parent.chmod(0o700)
        self.data = encoded(self.value)
        self.digest, self.record, self.rows = self.n['application_installation_plan'](self.data, self.n['bundle'])
        self.rollback_digest, self.owner, self.rows, self.marker = self.n['application_rollback_plan'](self.data, self.n['bundle'])
        self.capture = None

    def rollback(self):
        return self.n['application_rollback'](encoded(self.value), self.n['bundle'])

    def refused(self, message='.'):
        before = self.destinations()
        with self.assertRaisesRegex((ValueError, OSError), message): self.rollback()
        self.assertEqual(before, self.destinations()); self.assert_closed()

    def recorded(self):
        path = self.state / 'rollback.json'; path.write_bytes(self.marker); path.chmod(0o400)

    def run_delivered(self, fault=False):
        self.install(); self.manifest_file.write_bytes(encoded(self.value))
        original = emitted_program(); body, dispatch = original.split('action = sys.argv[1]\n', 1)
        seam = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                '_rollback_original_os = dep_os\n'
                '_rollback_private_root = ' + repr(str(self.root)) + '\n'
                'class _RollbackPrivateOS:\n'
                '    def __getattr__(self, name): return getattr(_rollback_original_os, name)\n'
                '    def open(self, path, flags, *args, **kwargs):\n'
                '        return _rollback_original_os.open(_rollback_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                'dep_os = _RollbackPrivateOS()\n')
        if fault:
            seam += ('_rollback_original_unlink = dep_os.unlink\n'
                     '_rollback_retired = 0\n'
                     'def _rollback_interrupt(leaf, *args, **kwargs):\n'
                     '    global _rollback_retired\n'
                     '    _rollback_retired += 1\n'
                     '    if _rollback_retired == 2: raise OSError("explicit second-unlink fault")\n'
                     '    return _rollback_original_unlink(leaf, *args, **kwargs)\n'
                     'dep_os.unlink = _rollback_interrupt\n')
        trampoline = ('try:\n'
                      '    result = application_rollback(deployment_read("/manifest.json"), bundle)\n'
                      'except (OSError, ValueError):\n'
                      '    print("Private application rollback model refused", file=dep_sys.stderr)\n'
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
                        'wait': result.returncode, 'explicit_second_unlink_fault': fault,
                        'before_destination_files': {n: {'bytes': len(v[0]), 'sha256': hashlib.sha256(v[0]).hexdigest(), 'mode': format(v[1], '04o')} for n,v in before_destinations.items()}}
        return result

    def test_complete_first_installation_returns_to_exact_destination_absence(self):
        self.install(); before = self.source_snapshot(); result = self.rollback()
        self.assertEqual(result['files'], 11); self.assertEqual(result['removed_files'], 11)
        self.assertEqual(result['disposition'], 'rolled-back'); self.assertEqual(result['publication_sha256'], self.digest)
        self.assertEqual(result['rollback_record_sha256'], hashlib.sha256(self.marker).hexdigest())
        self.assertTrue(result['checked_closes_completed']); self.assertTrue(result['file_and_directory_fsync_returned'])
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.assertEqual(stat.S_IMODE((self.state / 'rollback.json').stat().st_mode), 0o400)
        self.assertFalse((self.state / 'installation.json').exists())
        for row in self.rows: self.assertFalse(self.leaf(row).exists())
        self.assertEqual(before, self.source_snapshot()); self.assert_closed()

    def test_dual_family_restores_absence_of_both_public_gateways(self):
        self.value['public']['ipv6'] = net_fixture.PUBLIC6; self.install(); result = self.rollback()
        self.assertEqual(result['files'], 12); self.assertEqual(result['removed_files'], 12)
        for family in (4, 6): self.assertFalse((self.units / ('mk8-dns-gateway' + str(family) + '.service')).exists())
        self.assert_closed()

    def test_ipv6_only_restores_only_its_qualified_units(self):
        self.value['public'].update(ipv4=None, ipv6=net_fixture.PUBLIC6); self.install()
        self.assertEqual(self.rollback()['removed_files'], 11); self.assertEqual(list(self.units.iterdir()), [])
        self.assert_closed()

    def test_idempotent_retry_keeps_complete_marker_and_lock_identities(self):
        self.install(); self.rollback(); before = self.destinations()
        identities = {n: self.root.joinpath(n).stat() for n in before}
        result = self.rollback(); self.assertEqual(result['removed_files'], 0); self.assertEqual(result['disposition'], 'already-absent')
        self.assertEqual(before, self.destinations())
        for n,s in identities.items():
            current = self.root.joinpath(n).stat()
            self.assertEqual((current.st_ino,current.st_mtime_ns,current.st_ctime_ns), (s.st_ino,s.st_mtime_ns,s.st_ctime_ns))
        self.assert_closed()

    def test_marker_binds_complete_original_installation_record_and_publication(self):
        value = json.loads(self.marker); self.assertEqual(value['installation_record'], {'bytes': len(self.owner), 'sha256': hashlib.sha256(self.owner).hexdigest()})
        self.assertEqual(value['publication_sha256'], self.digest); self.assertEqual(value['files'], 11)
        self.assertEqual(value['restored_destination_state'], 'absent'); self.assertFalse(value['activation_authorized'])

    def test_all_authorities_false_and_no_production_dispatcher_or_default_call(self):
        self.install(); result = self.rollback(); self.assertEqual(len(result['authority']), 13)
        self.assertTrue(all(v is False for v in result['authority'].values()))
        dispatch = (ROOT / 'SSH/policy.sh.in').read_text().split('action = sys.argv[1]\n', 1)[1]
        self.assertNotIn('application_rollback(', dispatch)
        self.assertNotIn('application_rollback', (ROOT / 'Bootstrap/main.sh').read_text())
        self.assertFalse(result['authority']['service_stopped']); self.assert_closed()

    def test_missing_ownership_and_lock_refuses_without_creating_anything(self):
        self.refused(); self.assertEqual(list(self.state.iterdir()), [])

    def test_matching_unowned_unit_is_never_adopted_or_removed(self):
        path = self.leaf(); path.write_bytes(self.rows[0]['raw']); path.chmod(0o644)
        lock = self.state / '.installer.lock'; lock.write_bytes(self.n['APP_INSTALL_LOCK']); lock.chmod(0o400)
        self.refused('ownership required'); self.assertEqual(path.read_bytes(), self.rows[0]['raw'])

    def test_late_foreign_helper_preserves_every_earlier_installed_unit(self):
        self.install(); late = self.leaf(self.rows[-1]); late.write_bytes(b'foreign'); self.refused('prefix/content mismatch')
        self.assertFalse((self.state / 'rollback.json').exists())
        for row in self.rows[:-1]: self.assertTrue(self.leaf(row).exists())

    def test_late_symlink_and_hardlink_refuse_before_any_retirement(self):
        self.install(); path = self.leaf(self.rows[-1]); raw = path.read_bytes(); path.unlink()
        foreign = self.helpers / 'foreign'; foreign.write_bytes(raw); foreign.chmod(0o755)
        path.symlink_to(foreign); self.refused('unqualified owned'); path.unlink()
        os.link(foreign, path); self.refused('unqualified owned')
        self.assertFalse((self.state / 'rollback.json').exists())

    def test_wrong_final_mode_or_partial_final_content_is_not_deleted(self):
        self.install(); path = self.leaf(); path.chmod(0o640); self.refused('unqualified owned')
        path.chmod(0o644); path.write_bytes(self.rows[0]['raw'][:19]); self.refused('prefix/content mismatch')

    def test_exact_owned600_prefix_and_missing_rows_can_be_rolled_back(self):
        self.own(); lock = self.state / '.installer.lock'; lock.write_bytes(self.n['APP_INSTALL_LOCK']); lock.chmod(0o400)
        path = self.leaf(); path.write_bytes(self.rows[0]['raw'][:31]); path.chmod(0o600)
        self.assertEqual(self.rollback()['removed_files'], 1); self.assertFalse(path.exists()); self.assert_closed()

    def test_partial_ownership_record_refuses_without_rollback_marker(self):
        self.install(); path = self.state / 'installation.json'; path.chmod(0o600); path.write_bytes(self.owner[:41]); path.chmod(0o400)
        self.refused('publication bytes mismatch'); self.assertFalse((self.state / 'rollback.json').exists())

    def test_foreign_or_partial_rollback_marker_refuses_with_all_targets_preserved(self):
        self.install(); path = self.state / 'rollback.json'
        for raw in (self.marker[:31], b'foreign\n'):
            if path.exists(): path.chmod(0o600)
            path.write_bytes(raw); path.chmod(0o400); self.refused('publication bytes mismatch')

    def test_missing_installation_record_with_marker_requires_every_destination_absent(self):
        self.install(); self.recorded(); (self.state / 'installation.json').unlink()
        self.refused('destination unexpectedly present')

    def test_changed_manifest_cannot_reuse_old_owner_or_rollback_marker(self):
        self.install(); self.value['public']['ipv4'] = net_fixture.OTHER_PUBLIC4; self.refused('publication bytes mismatch')

    def test_foreign_state_entry_is_preserved_without_cleanup(self):
        self.install(); path = self.state / 'foreign'; path.write_bytes(b'preserve')
        self.refused('foreign rollback-state'); self.assertEqual(path.read_bytes(), b'preserve')

    def test_unrelated_units_helper_files_and_other_store_are_preserved(self):
        self.install(); files = [self.units / 'other-owner.service', self.helpers / 'other-helper']
        for p in files:p.write_bytes(b'foreign owner bytes')
        before = {str(p): p.stat() for p in files}; self.rollback()
        for p in files:
            self.assertEqual(p.stat(), before[str(p)]); self.assertEqual(p.read_bytes(), b'foreign owner bytes')
        self.assert_closed()

    def test_cooperative_installer_lock_contention_preserves_complete_tree(self):
        self.install()
        import fcntl
        with (self.state / '.installer.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); self.refused()
        self.assertFalse((self.state / 'rollback.json').exists())

    def test_interrupted_second_unlink_preserves_owner_then_retry_completes(self):
        self.install(); real = os.unlink; calls = 0
        def unlink(name, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('explicit second unlink failure')
            return real(name,*args,**kwargs)
        self.delivery.unlink = unlink
        with self.assertRaisesRegex(OSError, 'second unlink failure'): self.rollback()
        self.assertFalse(self.leaf().exists()); self.assertTrue(self.leaf(self.rows[1]).exists())
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.owner)
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        del self.delivery.unlink
        self.assertEqual(self.rollback()['removed_files'], 10); self.assert_closed()

    def test_marker_zero_write_refuses_before_the_first_unlink(self):
        self.install(); real = os.write; self.delivery.write = lambda fd,raw: 0 if raw==self.marker else real(fd,raw)
        self.delivery.unlink = Mock(side_effect=AssertionError('retirement forbidden'))
        with self.assertRaisesRegex(ValueError, 'incomplete publication write'): self.rollback()
        self.delivery.unlink.assert_not_called(); self.assertEqual((self.state / 'rollback.json').read_bytes(), b'')
        self.assertTrue(all(self.leaf(row).exists() for row in self.rows)); self.assert_closed()

    def test_marker_short_writes_complete_before_retirement(self):
        self.install(); real = os.write; self.delivery.write = lambda fd,raw: real(fd,raw[:11])
        self.assertEqual(self.rollback()['removed_files'], 11); self.assert_closed()

    def test_parent_sync_failure_after_unlink_is_not_success_and_retry_is_safe(self):
        self.install(); real = os.fsync; fired = False
        def sync(fd):
            nonlocal fired
            if not fired and os.readlink('/proc/self/fd/' + str(fd))==str(self.units) and not self.leaf().exists():
                fired = True; raise OSError('explicit parent sync fault')
            return real(fd)
        self.delivery.fsync = sync
        with self.assertRaisesRegex(OSError, 'parent sync fault'): self.rollback()
        self.assertTrue((self.state / 'installation.json').exists()); self.assertFalse(self.leaf().exists())
        del self.delivery.fsync; self.assertEqual(self.rollback()['removed_files'], 10); self.assert_closed()

    def test_owner_unlink_failure_retains_owner_for_zero_payload_retry(self):
        self.install(); real = os.unlink
        def unlink(name,*args,**kwargs):
            if name=='installation.json':raise OSError('explicit owner unlink fault')
            return real(name,*args,**kwargs)
        self.delivery.unlink = unlink
        with self.assertRaisesRegex(OSError, 'owner unlink fault'): self.rollback()
        self.assertTrue((self.state / 'installation.json').exists()); self.assertTrue(all(not self.leaf(row).exists() for row in self.rows))
        del self.delivery.unlink; self.assertEqual(self.rollback()['removed_files'], 0); self.assert_closed()

    def test_checked_close_failure_withholds_receipt_after_complete_retirement(self):
        self.install(); real = self.delivery.close; fired = False; held = {}
        locking = self.n['pub_fcntl']
        def flock(fd, operation):
            held['fd'] = fd
            return locking.flock(fd, operation)
        self.n['pub_fcntl'] = Mock(LOCK_EX=locking.LOCK_EX, LOCK_NB=locking.LOCK_NB)
        self.n['pub_fcntl'].flock.side_effect = flock
        def close(fd):
            nonlocal fired
            real(fd)
            if not fired and fd == held.get('fd'):
                fired=True;raise OSError('explicit lock close fault')
        self.delivery.close=close
        with self.assertRaisesRegex(OSError,'lock close fault'):self.rollback()
        self.assertTrue(all(not self.leaf(row).exists() for row in self.rows));self.assert_closed()
        del self.delivery.close;self.assertEqual(self.rollback()['disposition'],'already-absent')

    def test_failed_marker_file_sync_is_repeated_before_retry_can_unlink(self):
        self.install(); real_sync = os.fsync; fired = False; syncs = []
        def sync(fd):
            nonlocal fired
            name = os.readlink('/proc/self/fd/' + str(fd))
            if name == str(self.state / 'rollback.json'):
                if not fired:
                    fired = True; raise OSError('explicit marker file sync fault')
                syncs.append(name)
            return real_sync(fd)
        self.delivery.fsync = sync
        with self.assertRaisesRegex(OSError, 'marker file sync fault'): self.rollback()
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.assertTrue(all(self.leaf(row).exists() for row in self.rows))
        real_unlink = os.unlink
        def unlink(name, *args, **kwargs):
            self.assertTrue(syncs, 'retained marker must be file-synchronized before first deletion')
            return real_unlink(name, *args, **kwargs)
        self.delivery.unlink = unlink
        self.assertEqual(self.rollback()['removed_files'], 11); self.assertGreaterEqual(len(syncs), 2)
        self.assert_closed()

    def test_path_replacement_after_admission_refuses_before_marker_or_unlink(self):
        self.install(); original=self.n['installation_context'];calls=0
        def context(held,links):
            nonlocal calls
            calls+=1
            if calls==2:
                self.helpers.rename(self.helpers.parent/'previous');self.helpers.mkdir(mode=0o700)
            return original(held,links)
        self.n['installation_context']=context
        with self.assertRaisesRegex(ValueError,'installation (held ancestry|directory path) changed'):self.rollback()
        self.assertFalse((self.state/'rollback.json').exists());self.assertTrue(self.leaf().exists());self.assert_closed()

    def test_missing_fresh_raw_source_refuses_before_target_directory_reads(self):
        self.install();(self.root/'etc/mk8.email/gateway/database-password.txt').unlink()
        original=self.n['installation_directories'];self.n['installation_directories']=Mock(side_effect=AssertionError('destination IO forbidden'))
        try:
            with self.assertRaises(OSError):self.rollback()
            self.n['installation_directories'].assert_not_called()
        finally:self.n['installation_directories']=original

    def test_retained_rollback_marker_deliberately_blocks_unchanged_installer(self):
        self.install();self.rollback();before=self.destinations()
        with self.assertRaisesRegex(ValueError,'foreign installation-state'):self.install()
        self.assertEqual(before,self.destinations());self.assert_closed()

    def test_whole_delivered_library_positive_restores_owned_file_absence(self):
        result=self.run_delivered();self.assertEqual(result.returncode,0,result.stderr.decode());output=json.loads(result.stdout)
        self.assertEqual(output['removed_files'],11);self.assertEqual(len(output['authority']),13)
        self.assertTrue(all(v is False for v in output['authority'].values()))
        self.assertTrue(all(not self.leaf(row).exists() for row in self.rows))
        self.assertEqual((self.state/'rollback.json').read_bytes(),self.marker);self.assertFalse((self.state/'installation.json').exists())

    def test_whole_delivered_library_interruption_is_model75_with_owned_remainder(self):
        result=self.run_delivered(True);self.assertEqual(result.returncode,75);self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'Private application rollback model refused\n')
        self.assertFalse(self.leaf().exists());self.assertTrue(self.leaf(self.rows[1]).exists())
        self.assertEqual((self.state/'rollback.json').read_bytes(),self.marker)
        self.assertEqual((self.state/'installation.json').read_bytes(),self.owner)

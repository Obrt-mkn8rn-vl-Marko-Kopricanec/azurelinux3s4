"""Owned configuration retirement/reinstallation in explicit private roots only."""

import os
import stat
import unittest

import test_deployment_configuration_installation as installation_fixture
from test_deployment_policy import emitted_program, encoded


class ConfigurationLifecycleTests(unittest.TestCase):
    install = installation_fixture.ConfigurationInstallationTests.install
    leaf = installation_fixture.ConfigurationInstallationTests.leaf
    snapshot = installation_fixture.ConfigurationInstallationTests.snapshot
    closed = installation_fixture.ConfigurationInstallationTests.closed

    def setUp(self):
        installation_fixture.ConfigurationInstallationTests.setUp(self)
        for name in ('application_rollback', 'application_reinstallation', 'configuration_lifecycle'):
            path = installation_fixture.ROOT / 'Deployment' / (name + '.py')
            exec(compile(path.read_bytes(), str(path), 'exec'), self.n)
        _, _, _, self.marker = self.n['configuration_rollback_plan'](self.data, self.n['bundle'])

    def rollback(self):
        return self.n['configuration_rollback'](encoded(self.value), self.n['bundle'])

    def reinstall(self):
        return self.n['configuration_reinstallation'](encoded(self.value), self.n['bundle'])

    def absent(self):
        self.assertTrue(all(not self.leaf(index).exists() for index in range(5)))
        self.assertFalse((self.state / 'installation.json').exists())
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)

    def complete(self):
        for index, row in enumerate(self.rows):
            self.assertEqual((self.leaf(index).read_bytes(), stat.S_IMODE(self.leaf(index).stat().st_mode)),
                             (row['raw'], row['mode']))
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertFalse((self.state / 'rollback.json').exists())

    def test_complete_roundtrip_retry_and_separate_namespace_preserve_all_five_files(self):
        unrelated = self.root / 'unrelated'; unrelated.write_bytes(b'preserve')
        self.install()
        result = self.rollback()
        self.assertEqual((result['files'], result['removed_files']), (5, 5))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.absent()
        before = self.snapshot()
        self.assertEqual(self.rollback()['removed_files'], 0)
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(ValueError, 'foreign installation-state'): self.install()
        result = self.reinstall()
        self.assertEqual(result['installation']['changed_files'], 5)
        self.assertTrue(result['rollback_marker_observed'])
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertTrue(all(value is False for value in result['installation']['authority'].values()))
        self.complete()
        identities = {name: (self.root / name).stat().st_ino for name in self.snapshot()}
        result = self.reinstall()
        self.assertEqual(result['installation']['changed_files'], 0)
        self.assertFalse(result['rollback_marker_observed'])
        self.assertEqual({name: (self.root / name).stat().st_ino for name in self.snapshot()}, identities)
        self.assertEqual(unrelated.read_bytes(), b'preserve')
        self.assertFalse((self.root / self.n['APP_INSTALL_STATE'][1:]).exists())
        self.closed()

    def test_interrupted_second_retirement_preserves_owner_and_marker_for_exact_retry(self):
        self.install()
        original = self.delivery.unlink
        calls = []
        def interrupted(leaf, *args, **kwargs):
            calls.append(leaf)
            if len(calls) == 2: raise OSError('explicit second retirement fault')
            return original(leaf, *args, **kwargs)
        self.delivery.unlink = interrupted
        with self.assertRaisesRegex(OSError, 'second retirement'): self.rollback()
        self.assertFalse(self.leaf(0).exists())
        self.assertTrue(all(self.leaf(index).exists() for index in range(1, 5)))
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'unexpectedly present'): self.reinstall()
        self.assertEqual(self.snapshot(), before)
        self.delivery.unlink = original
        self.assertEqual(self.rollback()['removed_files'], 4)
        self.absent(); self.closed()

    def test_late_foreign_bytes_changed_plan_or_link_refuse_before_any_retirement(self):
        self.install()
        last = self.leaf(4)
        original = last.read_bytes(); last.write_bytes(b'foreign')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'mismatch'): self.rollback()
        self.assertEqual(self.snapshot(), before)
        last.write_bytes(original)
        alias = self.root / 'alias'; os.link(last, alias)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'leaf'): self.rollback()
        self.assertEqual(self.snapshot(), before)
        alias.unlink()
        self.value['mail']['pop3s'] = True
        before = self.snapshot()
        with self.assertRaises(ValueError): self.rollback()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.state / 'rollback.json').exists())
        self.closed()

    def test_marker_parent_sync_failure_and_private600_prefix_recovery_keep_exact_ownership(self):
        original_write = self.delivery.write
        self.delivery.write = lambda fd, raw: 0 if raw == self.rows[2]['raw'] else original_write(fd, raw)
        with self.assertRaisesRegex(ValueError, 'incomplete installation write'): self.install()
        self.delivery.write = original_write
        self.assertEqual(self.leaf(2).read_bytes(), b'')
        self.assertEqual(stat.S_IMODE(self.leaf(2).stat().st_mode), 0o600)
        original_sync = self.delivery.fsync
        def fail_state_sync(fd):
            if os.fstat(fd).st_ino == self.state.stat().st_ino:
                raise OSError('explicit marker-parent sync fault')
            original_sync(fd)
        self.delivery.fsync = fail_state_sync
        with self.assertRaisesRegex(OSError, 'marker-parent sync'): self.rollback()
        self.assertTrue(self.leaf(0).exists())
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.delivery.fsync = original_sync
        self.assertEqual(self.rollback()['removed_files'], 3)
        self.absent()
        self.delivery.write = lambda fd, raw: 0 if raw == self.rows[2]['raw'] else original_write(fd, raw)
        with self.assertRaisesRegex(ValueError, 'incomplete installation write'): self.reinstall()
        inode = self.leaf(2).stat().st_ino
        self.assertEqual(self.leaf(2).read_bytes(), b'')
        self.assertFalse((self.state / 'rollback.json').exists())
        self.delivery.write = original_write
        result = self.reinstall()
        self.assertFalse(result['rollback_marker_observed'])
        self.assertEqual(self.leaf(2).stat().st_ino, inode)
        self.complete(); self.closed()

    def test_partial_new_owner_preserves_complete_marker_and_refuses_adoption(self):
        self.install(); self.rollback()
        original = self.delivery.write
        self.delivery.write = lambda fd, raw: 0
        with self.assertRaises(ValueError): self.reinstall()
        self.delivery.write = original
        self.assertEqual((self.state / 'installation.json').read_bytes(), b'')
        self.assertEqual((self.state / 'rollback.json').read_bytes(), self.marker)
        self.assertTrue(all(not self.leaf(index).exists() for index in range(5)))
        before = self.snapshot()
        for operation in (self.install, self.rollback, self.reinstall):
            with self.assertRaises(ValueError): operation()
            self.assertEqual(self.snapshot(), before)
        self.closed()

    def test_whole_emitted_library_has_private_complete_cycle_but_no_production_dispatch(self):
        body, dispatch = emitted_program().split('action = sys.argv[1]\n', 1)
        for function in ('configuration_installation', 'configuration_rollback', 'configuration_reinstallation',
                         'installation_apply', 'rollback_apply', 'reinstallation_apply'):
            self.assertNotIn(function + '(', dispatch)
            self.assertNotIn(function, (installation_fixture.ROOT / 'Bootstrap/main.sh').read_text())
        namespace = {'__name__': 'configuration_private_complete_emission'}
        exec(compile(body, 'complete-shipped-library', 'exec'), namespace)
        namespace['dep_os'] = self.delivery
        namespace['DEP_TRUSTED_UID'] = os.geteuid()
        first = namespace['configuration_installation'](self.data, namespace['bundle'])
        retired = namespace['configuration_rollback'](self.data, namespace['bundle'])
        again = namespace['configuration_reinstallation'](self.data, namespace['bundle'])
        self.assertEqual((first['files'], retired['removed_files'], again['installation']['changed_files']), (5, 5, 5))
        self.assertTrue(all(value is False for value in again['authority'].values()))
        self.complete(); self.closed()

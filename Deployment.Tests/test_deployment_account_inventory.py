"""Local account-file observations in private roots, never native NSS/provisioning."""

import copy
import json
import os
import subprocess
import sys

import test_deployment_releases as fixture
from test_deployment_policy import encoded


class AccountInventoryTests(fixture.ReleaseFixture):
    def setUp(self):
        super().setUp()
        source = fixture.ROOT / 'Deployment/account_inventory.py'
        exec(compile(source.read_bytes(), str(source), 'exec'), self.n)
        self.units = self.n['application_bundle'](encoded(self.value), self.n['bundle'])['files']
        self.names = [row['name'] for row in self.n['application_account_policy'](self.units)['accounts']]
        self.inputs = {
            'passwd': b'root:x:0:0:root:/root:/bin/sh\n',
            'group': b'root:x:0:\n',
            'shadow': b'root:!:20000:0:99999:7:::\n',
            'gshadow': b'root:!::\n',
            'nsswitch.conf': b'passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files dns\n',
        }
        # Finite unrelated numeric test data, not an allocation/default.
        for number, name in enumerate(self.names, 2000):
            self.inputs['passwd'] += f'{name}:x:{number}:{number}:Application:/:/usr/sbin/nologin\n'.encode()
            self.inputs['group'] += f'{name}:x:{number}:\n'.encode()
            self.inputs['shadow'] += f'{name}:!:20000:0:99999:7:::\n'.encode()
            self.inputs['gshadow'] += f'{name}:!::\n'.encode()

    def observe(self, inputs=None):
        return self.n['account_inventory'](self.units, self.inputs if inputs is None else inputs)

    def write_inputs(self):
        for name, data in self.inputs.items():
            path = self.root / 'etc' / name
            path.write_bytes(data)
            path.chmod(self.n['ACCOUNT_FILES'][name])

    def change(self, inputs, kind, name, index, value):
        rows = [line.split(':') for line in inputs[kind].decode().splitlines()]
        row = next(row for row in rows if row[0] == name)
        row[index] = value
        inputs[kind] = ('\n'.join(':'.join(row) for row in rows) + '\n').encode()

    def issue(self, inputs, expected):
        before = copy.deepcopy(inputs)
        result = self.observe(inputs)
        self.assertFalse(result['all_present_and_locally_compatible'])
        self.assertIn(expected, result['accounts'][0]['issues'])
        self.assertEqual(inputs, before)
        return result

    def test_complete_private_cli_reports_local_declarations_without_writing_or_secrets(self):
        self.write_inputs()
        before = self.snapshot()
        child = subprocess.run([sys.executable, '-I', '-B', str(fixture.ROOT / 'Bootstrap/preflight.py'),
                                '--root', str(self.root), '--manifest', '/manifest.json', '--kind', 'accounts'],
                               capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        observation = result['account_observation']
        self.assertEqual(observation, self.observe())
        self.assertTrue(observation['all_present_and_locally_compatible'])
        self.assertEqual(len(observation['accounts']), 6)
        self.assertTrue(all(row['status'] == 'compatible-local-declarations' for row in observation['accounts']))
        self.assertTrue(all(value is False for value in observation['authority'].values()))
        self.assertEqual(len(result['files']), 14)
        self.assertNotIn(b'finite-model-only-password', child.stdout)
        self.assertNotIn(b'20000:0:99999', child.stdout)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'var').exists())
        self.assertFalse((self.root / 'usr').exists())

    def test_root_aliases_foreign_primary_group_and_numeric_mismatch_are_conflicts(self):
        cases = (
            ('passwd', 2, '0', 'root_numeric_identity'),
            ('group', 2, '0', 'root_numeric_identity'),
            ('passwd', 3, '2001', 'primary_group_mismatch'),
        )
        for kind, index, value, issue in cases:
            with self.subTest(issue=issue, kind=kind):
                inputs = dict(self.inputs)
                self.change(inputs, kind, self.names[0], index, value)
                self.issue(inputs, issue)
        for kind, line, issue in (
            ('passwd', b'alias:x:2000:3000::/:/bin/sh\n', 'uid_alias'),
            ('group', b'alias:x:2000:\n', 'gid_alias'),
            ('passwd', b'alias:x:3000:2000::/:/bin/sh\n', 'foreign_primary_group_user'),
        ):
            with self.subTest(issue=issue):
                inputs = dict(self.inputs); inputs[kind] += line
                self.issue(inputs, issue)

    def test_memberships_password_markers_home_shell_and_partial_rows_are_conflicts(self):
        for kind, index, value, issue in (
            ('passwd', 1, 'unlocked-private-value', 'password_source_not_shadow'),
            ('shadow', 1, 'unlocked-private-value', 'password_not_locked'),
            ('passwd', 5, '/home/foreign', 'unexpected_home_or_shell'),
            ('passwd', 6, '/bin/sh', 'unexpected_home_or_shell'),
            ('group', 1, '', 'group_password_not_locked'),
            ('gshadow', 1, '', 'group_password_not_locked'),
            ('group', 3, 'root', 'unexpected_group_member'),
            ('gshadow', 3, self.names[0], 'group_shadow_members_mismatch'),
            ('gshadow', 2, 'root', 'group_administrator_membership'),
        ):
            with self.subTest(kind=kind, index=index):
                inputs = dict(self.inputs)
                self.change(inputs, kind, self.names[0], index, value)
                result = self.issue(inputs, issue)
                self.assertNotIn('unlocked-private-value', json.dumps(result))
        for kind, field, issue in (('group', 3, 'supplementary_group_membership'),
                                   ('gshadow', 2, 'group_administrator_membership')):
            inputs = dict(self.inputs)
            self.change(inputs, kind, 'root', field, self.names[0])
            self.issue(inputs, issue)
        inputs = dict(self.inputs)
        inputs['shadow'] = b'root:!:20000:0:99999:7:::\n'
        self.issue(inputs, 'partial_account_records')

    def test_complete_record_syntax_bounds_and_late_malformed_rows_refuse(self):
        for kind, extra in (
            ('passwd', self.inputs['passwd'].splitlines(keepends=True)[-1]),
            ('passwd', b'late:x:01:2000::/:/bin/sh\n'),
            ('passwd', b'late:x:4294967295:2000::/:/bin/sh\n'),
            ('passwd', b'late:x:3000:3000:bad\tdata:/:/bin/sh\n'),
            ('group', b'late:x:3000:root,root\n'),
            ('shadow', b'late:!:20000:0:99999:7:::reserved\n'),
            ('gshadow', b'late:!::root:extra\n'),
            ('nsswitch.conf', b'passwd: files\n'),
            ('nsswitch.conf', b'invalid bare row\n'),
        ):
            with self.subTest(kind=kind, extra=extra):
                inputs = dict(self.inputs); inputs[kind] += extra
                with self.assertRaises(ValueError): self.observe(inputs)
        for value in (b'', b'root:x:0:\r\n', b'# no final LF', b'#' * (self.n['ACCOUNT_INPUT_LIMIT'] + 1) + b'\n',
                      b'#\n' * (self.n['ACCOUNT_ROW_LIMIT'] + 1)):
            with self.subTest(size=len(value)):
                inputs = dict(self.inputs); inputs['group'] = value
                with self.assertRaises(ValueError): self.observe(inputs)
        inputs = dict(self.inputs); inputs['unexpected'] = b'value\n'
        with self.assertRaises(ValueError): self.observe(inputs)

    def test_missing_accounts_and_nonlocal_or_incomplete_nss_never_claim_compatibility(self):
        for suffix in (b' systemd', b' ldap', b' [SUCCESS=return]'):
            inputs = dict(self.inputs)
            inputs['nsswitch.conf'] = inputs['nsswitch.conf'].replace(b'passwd: files', b'passwd: files' + suffix)
            result = self.observe(inputs)
            self.assertFalse(result['selected_nss_files_only'])
            self.assertFalse(result['all_present_and_locally_compatible'])
        for raw in (b'passwd: files\n', self.inputs['nsswitch.conf'] + b'initgroups: files systemd\n'):
            inputs = dict(self.inputs); inputs['nsswitch.conf'] = raw
            self.assertFalse(self.observe(inputs)['selected_nss_files_only'])
        inputs = {name: raw.splitlines(keepends=True)[0] for name, raw in self.inputs.items()}
        inputs['nsswitch.conf'] = self.inputs['nsswitch.conf']
        result = self.observe(inputs)
        self.assertTrue(all(row['status'] == 'absent' and row['uid'] is None and row['gid'] is None for row in result['accounts']))
        self.assertFalse(result['all_present_and_locally_compatible'])
        inputs['group'] += ('foreign:x:3000:' + self.names[0] + '\n').encode()
        self.issue(inputs, 'partial_account_records')

    def test_protected_private_observation_refuses_modes_and_aliases_without_mutation(self):
        self.write_inputs()
        path = self.root / 'etc/shadow'
        path.chmod(0o644)
        before = self.snapshot()
        with self.assertRaises(ValueError): self.n['account_inventory_observe'](self.units)
        self.assertEqual(self.snapshot(), before)
        path.chmod(0o600)
        alias = self.root / 'shadow-alias'; os.link(path, alias)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'unprotected or oversized release file'):
            self.n['account_inventory_observe'](self.units)
        self.assertEqual(self.snapshot(), before)
        alias.unlink()
        before = self.snapshot()
        result = self.n['account_inventory_observe'](self.units)
        self.assertEqual(result, self.observe())
        self.assertEqual(self.snapshot(), before)

"""Six fixed sysusers declarations and private publication/file-lifecycle delivery."""

import deployment_fixture as net_fixture

import copy
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
import test_deployment_application_installation as installation_fixture


class ApplicationAccountTests(ReleaseFixture):
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
        self.sysusers = self.root / self.n['APP_INSTALL_SYSUSERS'][1:]
        self.store = self.root / self.n['APP_PUB_STORE'][1:]
        for path in (self.state, self.units, self.helpers, self.sysusers, self.store):
            path.mkdir(parents=True, mode=0o700)
            for parent in path.parents:
                if parent == self.root.parent: break
                parent.chmod(0o700)
        self.candidate = self.n['application_bundle'](encoded(self.value), self.n['bundle'])
        self.digest, self.record, self.rows = self.n['application_installation_plan'](encoded(self.value), self.n['bundle'])
        self.capture = None

    def policy(self, units=None):
        return self.n['application_account_policy'](self.candidate['files'] if units is None else units)

    def changed(self, row, old, new):
        row['content'] = row['content'].replace(old, new)
        raw = row['content'].encode('ascii'); row['bytes'] = len(raw); row['sha256'] = hashlib.sha256(raw).hexdigest()

    def refused(self, units, message='.'):
        before = copy.deepcopy(units)
        with self.assertRaisesRegex((ValueError, OSError), message): self.policy(units)
        self.assertEqual(units, before)

    def run_delivered(self, foreign=False):
        self.manifest_file.write_bytes(encoded(self.value))
        if foreign:
            path = self.sysusers / 'azurelinux3s4-applications.conf'; path.write_bytes(b'foreign owner bytes\n'); path.chmod(0o644)
        original = emitted_program(); body, dispatch = original.split('action = sys.argv[1]\n', 1)
        seam = ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
                '_accounts_original_os = dep_os\n'
                '_accounts_private_root = ' + repr(str(self.root)) + '\n'
                'class _AccountsPrivateOS:\n'
                '    def __getattr__(self, name): return getattr(_accounts_original_os, name)\n'
                '    def open(self, path, flags, *args, **kwargs):\n'
                '        return _accounts_original_os.open(_accounts_private_root if path == "/" else path, flags, *args, **kwargs)\n'
                'dep_os = _AccountsPrivateOS()\n')
        trampoline = ('try:\n'
                      '    result = application_installation(deployment_read("/manifest.json"), bundle)\n'
                      'except (OSError, ValueError):\n'
                      '    print("Private application accounts model refused", file=dep_sys.stderr)\n'
                      '    raise SystemExit(75)\n'
                      'print(publication_encoded(result).decode("ascii"), end="")\n')
        code = body + seam + trampoline; before = self.source_snapshot()
        result = subprocess.run([sys.executable, '-I', '-'], input=code.encode('ascii'),
                                capture_output=True, timeout=45, check=False)
        self.assertEqual(before, self.source_snapshot())
        self.capture = {'program': code, 'original_dispatch': 'action = sys.argv[1]\n' + dispatch,
                        'private_seam': seam, 'private_trampoline': trampoline,
                        'original_program_sha256': hashlib.sha256(original.encode('ascii')).hexdigest(),
                        'input': self.manifest_file.read_bytes().decode('ascii'),
                        'stdout': result.stdout.decode('ascii'), 'stderr': result.stderr.decode('ascii'),
                        'wait': result.returncode, 'foreign_existing_sysusers_file_setup': foreign}
        return result

    def test_six_named_accounts_bind_every_complete_unit_and_leave_ids_null(self):
        value = self.policy(); self.assertEqual(len(value['accounts']), 6)
        self.assertEqual([row['name'] for row in value['accounts']],
                         ['mk8sava-application', 'mk8sava-gateway', 'mk8drava', 'mk8dns', 'mk8email-worker', 'mk8email-gateway'])
        self.assertEqual([row['file'] for row in value['units']], [row['file'] for row in self.candidate['files']])
        for account in value['accounts']:
            self.assertIsNone(account['uid']); self.assertIsNone(account['gid'])
            self.assertEqual(account['primary_group'], account['name'])
            owners = [row for row in value['units'] if row['user'] == account['name']]
            self.assertEqual(account['units'], [row['file'] for row in owners])
            self.assertTrue(all(row['group'] == account['name'] for row in owners))
        self.assertEqual({row['sha256'] for row in value['units']}, {row['sha256'] for row in self.candidate['files']})

    def test_sysusers_lines_have_only_fixed_u_names_auto_ids_root_home_and_nologin(self):
        value = self.policy(); file = value['file']; lines = file['content'].splitlines()[1:]
        self.assertEqual(file['file'], 'usr/lib/sysusers.d/azurelinux3s4-applications.conf')
        self.assertEqual(file['mode'], '0644'); self.assertEqual(len(lines), 6)
        self.assertEqual(lines, ['u ' + row['name'] + ' - "Application service account" / /usr/sbin/nologin' for row in value['accounts']])
        raw = file['content'].encode('ascii'); self.assertEqual(file['bytes'], len(raw))
        self.assertEqual(file['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('u root ', file['content']); self.assertNotIn('\nm ', file['content']); self.assertNotIn('\nr ', file['content'])

    def test_ipv6_only_and_dual_family_share_exact_account_text_with_full_unit_bindings(self):
        baseline = self.policy()['file']
        for public in ((None, net_fixture.PUBLIC6), (net_fixture.PUBLIC4, net_fixture.PUBLIC6)):
            self.value['public'].update(ipv4=public[0], ipv6=public[1])
            value = self.policy(self.n['application_bundle'](encoded(self.value), self.n['bundle'])['files'])
            self.assertEqual(value['file'], baseline); self.assertEqual(len(value['accounts']), 6)
            self.assertTrue(any(row['file'].endswith('gateway6.service') for row in value['units']))

    def test_different_sava_and_email_names_and_shared_drava_dns_are_explicit_declarations(self):
        value = self.policy(); owners = {row['name']: row['units'] for row in value['accounts']}
        self.assertEqual(len(owners['mk8drava']), 2); self.assertEqual(len(owners['mk8dns']), 3)
        for name in ('mk8sava-application', 'mk8sava-gateway', 'mk8email-worker', 'mk8email-gateway'):
            self.assertEqual(len(owners[name]), 1)
        self.assertFalse(value['authority']['uids_gids_allocated']); self.assertFalse(value['authority']['service_credential_access_proven'])

    def test_all_ten_authorities_false_without_current_account_or_native_claims(self):
        value = self.policy(); self.assertEqual(len(value['authority']), 10)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertTrue(any('Existing users/groups are not repaired' in limit for limit in value['limits']))
        self.assertTrue(any('consumed at boot' in limit for limit in value['limits']))
        self.assertTrue(any('No home directory is created' in limit for limit in value['limits']))

    def test_pure_compiler_performs_no_os_read_write_or_native_call(self):
        original = self.n['dep_os']; blocked = Mock(side_effect=AssertionError('OS operation forbidden'))
        self.n['dep_os'] = blocked
        try: self.assertEqual(len(self.policy()['accounts']), 6)
        finally: self.n['dep_os'] = original
        blocked.assert_not_called()

    def test_late_wrong_user_recomputed_hash_cannot_borrow_valid_earlier_units(self):
        units = copy.deepcopy(self.candidate['files']); self.changed(units[-1], 'User=mk8email-gateway', 'User=root')
        self.refused(units, 'exact service account correspondence')

    def test_late_wrong_group_recomputed_hash_refuses(self):
        units = copy.deepcopy(self.candidate['files']); self.changed(units[-1], 'Group=mk8email-gateway', 'Group=root')
        self.refused(units, 'exact service account correspondence')

    def test_duplicate_or_reset_user_group_refuses_before_output(self):
        for key in ('User', 'Group'):
            units = copy.deepcopy(self.candidate['files'])
            self.changed(units[-1], key + '=mk8email-gateway', key + '=mk8email-gateway\n' + key + '=')
            self.refused(units, 'single service User/Group')

    def test_user_group_in_install_section_are_not_native_service_identity(self):
        units = copy.deepcopy(self.candidate['files'])
        self.changed(units[-1], 'User=mk8email-gateway\n', '')
        self.changed(units[-1], '[Install]\n', '[Install]\nUser=mk8email-gateway\n')
        self.refused(units, 'single service User/Group')

    def test_every_unsupported_identity_modifier_refuses_even_when_false(self):
        for key in ('DynamicUser', 'SupplementaryGroups', 'PAMName', 'RootDirectory', 'RootImage', 'PrivateUsers'):
            units = copy.deepcopy(self.candidate['files']); self.changed(units[-1], '[Service]\n', '[Service]\n' + key + '=false\n')
            self.refused(units, 'unsupported account identity modifier')

    def test_whitespace_key_and_append_aliases_cannot_hide_duplicate_native_identity(self):
        for line in (' User=root', 'User =root', 'User+=root', ' Group=root'):
            units = copy.deepcopy(self.candidate['files']); self.changed(units[-1], '[Service]\n', '[Service]\n' + line + '\n')
            self.refused(units, 'canonical account unit directive')

    def test_nonascii_control_tab_and_missing_final_lf_refuse_original_unit_bytes(self):
        for tail in ('\t', '\r', '\x00', '\u2028', ''):
            units = copy.deepcopy(self.candidate['files']); row = units[-1]
            row['content'] = row['content'][:-1] + tail
            if tail == '\u2028': self.refused(units); continue
            raw = row['content'].encode('ascii'); row['bytes'] = len(raw); row['sha256'] = hashlib.sha256(raw).hexdigest()
            self.refused(units, 'byte commitment')

    def test_typed_fields_and_complete_hash_length_mode_checks_refuse(self):
        for key, value in (('bytes', True), ('bytes', 1), ('mode', '0755'), ('mode', None),
                           ('sha256', '0'*64), ('sha256', True), ('content', None), ('content', 'A'*65537)):
            units = copy.deepcopy(self.candidate['files']); units[-1][key] = value; self.refused(units)

    def test_missing_duplicate_reordered_and_extra_unit_rows_refuse(self):
        original = self.candidate['files']
        for units in (original[:-1], original+[original[-1]], list(reversed(original)), original[:-1]+[original[0]]):
            self.refused(copy.deepcopy(units))

    def test_unknown_unit_or_path_alias_refuses_fixed_role_namespace(self):
        for path in ('systemd/mk8-other-root.service', 'systemd/../mk8-email-gateway.service',
                     '/etc/systemd/system/mk8-email-gateway.service', True):
            units = copy.deepcopy(self.candidate['files']); units[-1]['file'] = path; self.refused(units)

    def test_second_service_section_and_unknown_section_refuse(self):
        for header in ('[Service]', '[Socket]'):
            units = copy.deepcopy(self.candidate['files']); self.changed(units[-1], '[Install]', header)
            self.refused(units)

    def test_missing_original_token_refuses_before_publication_store_io(self):
        (self.root / 'etc/mk8.drava/ipc-token.txt').unlink()
        store = Mock(side_effect=AssertionError('store IO forbidden'))
        self.n['publication_store'] = store
        with self.assertRaises((ValueError, OSError)):
            self.n['application_publication_publish'](encoded(self.value), self.n['bundle'])
        store.assert_not_called(); self.assert_closed()

    def test_late_identity_refusal_precedes_store_io_under_explicit_producer_fault_model(self):
        original = self.n['application_bundle']; store = Mock(side_effect=AssertionError('store IO forbidden'))
        def faulty(data, producer):
            result = original(data, producer); self.changed(result['files'][-1], 'User=mk8email-gateway', 'User=root'); return result
        self.n['application_bundle'] = faulty; self.n['publication_store'] = store
        with self.assertRaisesRegex(ValueError, 'exact service account correspondence'):
            self.n['application_publication_publish'](encoded(self.value), self.n['bundle'])
        store.assert_not_called(); self.assertEqual(list(self.store.iterdir()), []); self.assert_closed()

    def test_inactive_publication_binds_all_six_accounts_and_exact_stored0400_file(self):
        digest, contents = self.n['application_publication_plan'](encoded(self.value), self.n['bundle'])
        value = self.n['application_publication_publish'](encoded(self.value), self.n['bundle'])
        file = self.store / digest / 'sysusers/azurelinux3s4-applications.conf'
        self.assertEqual(value['stored_files'], 14); self.assertEqual(file.read_bytes(), self.policy()['file']['content'].encode('ascii'))
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o400)
        intent = json.loads(contents['publication.json']); self.assertEqual(len(intent['service_account_policy']['accounts']), 6)
        self.assertTrue(all(flag is False for flag in intent['service_account_policy']['authority'].values()))
        row = next(row for row in intent['files'] if row['stored'].startswith('sysusers/'))
        self.assertEqual(row['file'], self.n['APP_ACCOUNT_FILE']); self.assertEqual(row['mode'], '0644')
        self.assertEqual(row['sha256'], hashlib.sha256(file.read_bytes()).hexdigest()); self.assert_closed()

    def test_private_installer_delivers_sysusers0644_with_full_ownership_and_no_accounts_claim(self):
        result = self.install(); path = self.sysusers / 'azurelinux3s4-applications.conf'
        self.assertEqual(result['files'], 11); self.assertEqual(result['changed_files'], 11)
        self.assertEqual(path.read_bytes(), self.policy()['file']['content'].encode('ascii'))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644); self.assertFalse(result['authority']['accounts_provisioned'])
        owner = json.loads((self.state / 'installation.json').read_bytes())
        self.assertTrue(any(row['file'] == '/' + self.n['APP_ACCOUNT_FILE'] for row in owner['files'])); self.assert_closed()

    def test_file_rollback_retires_sysusers_fragment_without_native_account_rollback_claim(self):
        self.install(); result = self.n['application_rollback'](encoded(self.value), self.n['bundle'])
        self.assertEqual(result['removed_files'], 11); self.assertFalse((self.sysusers / 'azurelinux3s4-applications.conf').exists())
        self.assertEqual(list(self.sysusers.iterdir()), []); self.assertFalse(result['authority']['operationally_authorized'])
        self.assertFalse(result['authority']['configuration_rolled_back']); self.assert_closed()

    def test_reinstallation_recreates_exact_sysusers_file_and_keeps_all_authorities_false(self):
        self.install(); self.n['application_rollback'](encoded(self.value), self.n['bundle'])
        result = self.n['application_reinstallation'](encoded(self.value), self.n['bundle'])
        self.assertEqual(result['installation']['files'], 11)
        self.assertEqual((self.sysusers / 'azurelinux3s4-applications.conf').read_bytes(), self.policy()['file']['content'].encode('ascii'))
        self.assertTrue(all(flag is False for flag in result['authority'].values()))
        self.assertFalse(result['installation']['authority']['accounts_provisioned']); self.assert_closed()

    def test_ownership_missing_current_sysusers_row_is_not_silently_migrated(self):
        self.install(); path = self.state / 'installation.json'; value = json.loads(path.read_bytes())
        value['files'] = [row for row in value['files'] if row['file'] != '/' + self.n['APP_ACCOUNT_FILE']]
        path.chmod(0o600); path.write_bytes(encoded(value)); path.chmod(0o400); before = self.destinations()
        with self.assertRaisesRegex(ValueError, 'publication bytes mismatch'): self.install()
        self.assertEqual(self.destinations(), before); self.assert_closed()

    def test_foreign_sysusers_file_refuses_before_any_state_or_unit_write(self):
        path = self.sysusers / 'azurelinux3s4-applications.conf'; path.write_bytes(b'foreign\n'); path.chmod(0o644)
        before = self.destinations()
        with self.assertRaisesRegex(ValueError, 'lacks exact installation ownership'): self.install()
        self.assertEqual(self.destinations(), before); self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(list(self.units.iterdir()), []); self.assert_closed()

    def test_linked_sysusers_file_refuses_without_writing_through_alias(self):
        self.install(); path = self.sysusers / 'azurelinux3s4-applications.conf'; alias = self.root / 'other-owner'
        path.rename(alias); os.link(alias, path); before = alias.read_bytes()
        with self.assertRaisesRegex(ValueError, 'unqualified owned installation'): self.install()
        self.assertEqual(alias.read_bytes(), before); self.assertEqual(alias.stat().st_nlink, 2); self.assert_closed()

    def test_missing_sysusers_directory_is_never_implicitly_created(self):
        self.sysusers.rmdir()
        with self.assertRaises(FileNotFoundError): self.install()
        self.assertFalse(self.sysusers.exists()); self.assertEqual(list(self.state.iterdir()), []); self.assert_closed()

    def test_partial_final_sysusers_file_is_not_completed_or_adopted(self):
        self.install(); path = self.sysusers / 'azurelinux3s4-applications.conf'; path.write_bytes(path.read_bytes()[:31])
        before = self.destinations()
        with self.assertRaisesRegex(ValueError, 'prefix/content mismatch'): self.install()
        self.assertEqual(self.destinations(), before); self.assert_closed()

    def test_whole_delivered_current_policy_and_eleven_files_remain_private_model(self):
        result = self.run_delivered(); self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout); self.assertEqual(value['files'], 11)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertFalse(value['authority']['accounts_provisioned'])
        self.assertEqual((self.sysusers / 'azurelinux3s4-applications.conf').read_bytes(), self.policy()['file']['content'].encode('ascii'))
        self.assertEqual(stat.S_IMODE((self.sysusers / 'azurelinux3s4-applications.conf').stat().st_mode), 0o644)
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record); self.assert_closed()

    def test_whole_delivered_foreign_sysusers_is_model75_without_early_file_writes(self):
        result = self.run_delivered(foreign=True); self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'Private application accounts model refused\n')
        self.assertEqual((self.sysusers / 'azurelinux3s4-applications.conf').read_bytes(), b'foreign owner bytes\n')
        self.assertEqual(list(self.state.iterdir()), []); self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(list(self.helpers.iterdir()), []); self.assert_closed()

"""Fixed inactive PostgreSQL declarations and finite authentication-route models."""

import deployment_fixture as net_fixture

import copy
import hashlib
import ipaddress
import json
import unittest
from unittest.mock import Mock

import test_deployment_policy as policy_fixture


def route(text, transport, database, user, address=None):
    # Finite DATA model for ONLY this producer's fixed literal HBA subset.
    # Not a native parser, credential check, peer identity or loaded-rule proof.
    for line in text.splitlines():
        fields = line.split()
        kind, databases, users = fields[:3]
        if kind != transport or databases not in ('all', database) or user not in users.split(',') and users != 'all':
            continue
        if kind == 'host' and ipaddress.ip_address(address) not in ipaddress.ip_network(fields[3]):
            continue
        return fields[-1]
    return None


class PostgreSQLProfileTests(unittest.TestCase):
    def setUp(self):
        self.n = policy_fixture.library()

    def profile(self):
        return self.n['postgresql_profile']()

    def candidate(self, value=None):
        return self.n['deployment_bundle'](policy_fixture.encoded(value or policy_fixture.manifest()), self.n['bundle'])

    def test_complete_candidate_binds_same_profile_to_two_original_file_slots_and_contract(self):
        value = self.candidate(); files, requirements = self.profile()
        self.assertEqual(tuple(value['files'][2:4]), files)
        self.assertEqual(len(value['files']), 5)
        contract = json.loads(value['files'][4]['content'])
        self.assertEqual(contract['postgresql_prerequisites'], requirements)
        for row in (*files, value['files'][4]):
            raw = row['content'].encode('ascii')
            self.assertEqual(row['bytes'], len(raw)); self.assertEqual(row['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(row['mode'], '0600'); self.assertTrue(raw.endswith(b'\n'))

    def test_dns_unix_scram_precedes_final_local_reject_without_a_peer_role_grant(self):
        _, hba = self.profile()[0]
        self.assertEqual(route(hba['content'], 'local', 'mk8dns', 'mk8dns'), 'scram-sha-256')
        self.assertLess(hba['content'].index('local mk8dns mk8dns scram-sha-256'),
                        hba['content'].index('local all all reject'))
        self.assertNotIn('local mk8dns mk8dns peer', hba['content'])

    def test_local_superuser_peer_is_separate_from_dns_and_other_role_name_routes(self):
        text = self.profile()[0][1]['content']
        self.assertEqual(route(text, 'local', 'postgres', 'postgres'), 'peer')
        for user in ('mk8dns', 'mk8email_worker', 'mk8email_gateway', 'other'):
            self.assertEqual(route(text, 'local', 'postgres', user), 'reject')
        self.assertEqual(route(text, 'local', 'mk8email', 'mk8email_gateway'), 'reject')

    def test_both_email_logins_match_only_their_database_on_both_loopback_families(self):
        text = self.profile()[0][1]['content']
        for user in ('mk8email_worker', 'mk8email_gateway'):
            for address in ('127.0.0.1', '::1'):
                self.assertEqual(route(text, 'host', 'mk8email', user, address), 'scram-sha-256')
                for database in ('postgres', 'mk8dns', 'other'):
                    self.assertEqual(route(text, 'host', database, user, address), 'reject')

    def test_old_shared_email_login_and_postgres_are_not_tcp_client_selectors(self):
        text = self.profile()[0][1]['content']
        for user in ('mk8email', 'postgres', 'other'):
            for address in ('127.0.0.1', '::1'):
                self.assertEqual(route(text, 'host', 'mk8email', user, address), 'reject')

    def test_dns_loopback_tcp_rows_are_distinct_optional_authentication_paths_not_controller_transport(self):
        files, requirements = self.profile(); text = files[1]['content']
        for address in ('127.0.0.1', '::1'):
            self.assertEqual(route(text, 'host', 'mk8dns', 'mk8dns', address), 'scram-sha-256')
        self.assertEqual(requirements['dns_controller']['transport'], 'one absolute Unix socket directory')
        self.assertFalse(requirements['authority']['application_connection_strings_reconciled'])

    def test_every_public_admin_nonloopback_and_alternate_loopback_address_routes_to_reject(self):
        text = self.profile()[0][1]['content']
        for address in (net_fixture.admin4(10), net_fixture.nat4(), net_fixture.PUBLIC4, '127.0.0.2',
                        net_fixture.PUBLIC6, net_fixture.admin6(10), '::2'):
            for database, user in (('mk8dns', 'mk8dns'), ('mk8email', 'mk8email_worker'), ('mk8email', 'mk8email_gateway')):
                self.assertEqual(route(text, 'host', database, user, address), 'reject')

    def test_role_case_alias_and_injected_names_do_not_match_fixed_literal_user_lists(self):
        text = self.profile()[0][1]['content']
        for user in ('MK8EMAIL_GATEWAY', 'mk8email_gateway ', '+mk8email_gateway',
                     'mk8email_gateway,other', 'mk8email_gateway\n', '*', 'all'):
            self.assertEqual(route(text, 'host', 'mk8email', user, '127.0.0.1'), 'reject')

    def test_finite_first_match_model_does_not_fall_back_from_scram_to_peer(self):
        text = self.profile()[0][1]['content'] + 'local mk8dns mk8dns peer\n'
        self.assertEqual(route(text, 'local', 'mk8dns', 'mk8dns'), 'scram-sha-256')
        changed = 'local mk8dns mk8dns reject\n' + text
        self.assertEqual(route(changed, 'local', 'mk8dns', 'mk8dns'), 'reject')

    def test_finite_omit_new_unix_row_sensitivity_changes_dns_route_to_reject(self):
        text = self.profile()[0][1]['content']
        changed = text.replace('local mk8dns mk8dns scram-sha-256\n', '')
        self.assertEqual(route(text, 'local', 'mk8dns', 'mk8dns'), 'scram-sha-256')
        self.assertEqual(route(changed, 'local', 'mk8dns', 'mk8dns'), 'reject')

    def test_config_explicitly_declares_one_socket_directory_loopback_only_and_durability(self):
        text = self.profile()[0][0]['content']; values = dict(line.split(' = ', 1) for line in text.splitlines())
        self.assertEqual(values, {'listen_addresses': "'127.0.0.1,::1'", 'port': '5432',
            'password_encryption': "'scram-sha-256'", 'unix_socket_directories': "'/run/postgresql'",
            'fsync': 'on', 'full_page_writes': 'on', 'synchronous_commit': 'on'})
        self.assertNotIn('*', text); self.assertNotIn('/tmp', text)

    def test_fsync_full_page_and_synchronous_commit_are_separate_source_requirements(self):
        _, requirements = self.profile(); settings = requirements['required_observed_settings']
        for key in ('fsync', 'full_page_writes', 'synchronous_commit'):
            self.assertEqual(settings[key], 'on')
        self.assertFalse(requirements['authority']['durability_and_backup_restore_proven'])

    def test_minimum17_feature_floor_refuses_16_in_finite_comparison_without_approving17_runtime(self):
        _, requirements = self.profile(); floor = requirements['minimum_server_version_num']
        self.assertEqual(floor, 170000); self.assertEqual(requirements['required_privilege_vocabulary'], ['MAINTAIN'])
        self.assertLess(160015, floor); self.assertGreaterEqual(170002, floor)
        self.assertFalse(requirements['authority']['current_native_version_and_features_proven'])
        self.assertFalse(requirements['authority']['package_and_server_authenticated'])

    def test_read_only_probe_contains_only_settings_query_and_whole_byte_commitments(self):
        query = self.profile()[1]['future_read_only_settings_query']; raw = query['sql'].encode('ascii')
        self.assertEqual(query['bytes'], len(raw)); self.assertEqual(query['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(query['sql'].startswith('SELECT ')); self.assertTrue(query['sql'].endswith(';\n'))
        for token in ('ALTER ', 'CREATE ', 'DROP ', 'GRANT ', 'REVOKE ', 'SET ', 'COPY ', '\\gexec', 'MAINTAIN'):
            self.assertNotIn(token, query['sql'])
        self.assertEqual(query['sql'].count('current_setting('), 7)

    def test_all_probe_columns_match_declared_settings_and_include_raw_version_number(self):
        files, requirements = self.profile(); query = requirements['future_read_only_settings_query']['sql']
        for key in ('server_version_num', 'listen_addresses', 'port', 'unix_socket_directories',
                    'fsync', 'full_page_writes', 'synchronous_commit'):
            self.assertIn("current_setting('" + key + "')", query)
            self.assertIn(' AS ' + key, query)
        self.assertEqual(requirements['required_observed_settings']['unix_socket_directories'], '/run/postgresql')
        self.assertIn("unix_socket_directories = '/run/postgresql'", files[0]['content'])

    def test_compiler_never_calls_local_io_native_subprocess_or_installed_database(self):
        system = Mock(side_effect=AssertionError('no IO permitted')); original = self.n['dep_os']; self.n['dep_os'] = system
        try: self.profile(); system.assert_not_called()
        finally: self.n['dep_os'] = original

    def test_profile_has_no_supplied_version_role_query_or_planner_input(self):
        for argument in (16, 17, {'server_version_num': 170002}, lambda: {}, 'ALTER ROLE postgres SUPERUSER'):
            with self.assertRaises(TypeError): self.n['postgresql_profile'](argument)

    def test_returned_profile_mutations_cannot_poison_later_compilation_or_share_authority(self):
        files, requirements = self.profile(); baseline = self.profile()
        files[0]['content'] = 'listen_addresses = \'*\'\n'; requirements['authority']['server_ready'] = True
        requirements['email']['gateway_login_role'] = 'postgres'; requirements['required_privilege_vocabulary'].append('SUPERUSER')
        self.assertEqual(self.profile(), baseline)

    def test_same_compiler_profile_is_independent_of_admin_and_public_address_families(self):
        baseline = self.profile()
        for ipv4, ipv6 in ((net_fixture.nat4(), None), (None, net_fixture.PUBLIC6), (net_fixture.nat4(), net_fixture.PUBLIC6)):
            value = policy_fixture.manifest(False); value['public'].update(ipv4=ipv4, ipv6=ipv6)
            candidate = self.candidate(value); self.assertEqual(tuple(candidate['files'][2:4]), baseline[0])
            self.assertTrue(all(flag is False for flag in candidate['authority'].values()))

    def test_all_new_and_inherited_authorities_withhold_parser_loading_roles_schema_and_health(self):
        requirements = self.profile()[1]
        self.assertEqual(len(requirements['authority']), 12)
        self.assertTrue(all(flag is False for flag in requirements['authority'].values()))
        candidate = self.candidate(); self.assertTrue(all(flag is False for flag in candidate['authority'].values()))
        self.assertFalse(requirements['authority']['application_connection_strings_reconciled'])
        self.assertFalse(requirements['authority']['gateway_restricted_privileges_proven'])

    def test_prospective_names_do_not_claim_current_application_roles_or_credentials(self):
        requirements = self.profile()[1]
        self.assertEqual(requirements['dns_controller']['login_role'], 'mk8dns')
        self.assertEqual(requirements['email']['worker_login_role'], 'mk8email_worker')
        self.assertEqual(requirements['email']['gateway_login_role'], 'mk8email_gateway')
        self.assertNotEqual(requirements['email']['worker_login_role'], requirements['email']['gateway_login_role'])
        self.assertFalse(requirements['authority']['roles_and_passwords_provisioned'])
        self.assertFalse(requirements['authority']['application_connection_strings_reconciled'])

    def test_gateway_role_probe_and_dns_epoch_requirements_remain_explicit_future_checks(self):
        requirements = self.profile()[1]
        self.assertTrue(requirements['email']['gateway_requires_authenticated_login_restricted_role_probe'])
        self.assertTrue(requirements['dns_controller']['requires_original_epoch_and_writer_lease'])
        text = '\n'.join(requirements['prerequisites'])
        for phrase in ('17+', 'Gateway role', 'complete loaded', 'power-loss', 'actual DNS DSN'):
            self.assertIn(phrase, text)

    def test_invalid_manifest_refuses_before_profile_factory_even_with_supplied_stale_requirements(self):
        value = policy_fixture.manifest(); value['postgresql_prerequisites'] = self.profile()[1]
        original = self.n['postgresql_profile']; factory = Mock(); self.n['postgresql_profile'] = factory
        try:
            with self.assertRaisesRegex(ValueError, 'exact manifest'): self.candidate(value)
            factory.assert_not_called()
        finally: self.n['postgresql_profile'] = original

    def test_complete_inactive_files_never_contain_role_creation_password_or_cluster_commands(self):
        candidate = self.candidate(); text = '\n'.join(row['content'] for row in candidate['files'][2:])
        for command in ('CREATE ROLE', 'ALTER ROLE', 'CREATE DATABASE', 'initdb ', 'systemctl start', 'pg_ctl start', 'PASSWORD '):
            self.assertNotIn(command, text)
        self.assertTrue(all(flag is False for flag in candidate['authority'].values()))

    def test_authentication_model_is_not_a_positive_native_parser_role_or_password_receipt(self):
        files, requirements = self.profile()
        self.assertEqual(route(files[1]['content'], 'host', 'mk8email', 'mk8email_gateway', '::1'), 'scram-sha-256')
        for key in ('native_configuration_parsed', 'complete_loaded_configuration_admitted',
                    'roles_and_passwords_provisioned', 'gateway_restricted_privileges_proven', 'server_ready'):
            self.assertFalse(requirements['authority'][key])


if __name__ == '__main__':
    unittest.main()

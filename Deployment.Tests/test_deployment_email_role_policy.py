"""Declared role/state ownership and LAN admin inputs, without account operations."""

import deployment_fixture as net_fixture

import copy
import hashlib
import json
import unittest
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ReleaseFixture
import test_deployment_services as service_fixture


class EmailRolePolicyTests(ReleaseFixture):
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = service_fixture.DeploymentApplicationServiceTests.run_emitted

    def control(self, role='gateway'):
        return json.loads((self.root / 'etc/mk8.email' / (role + '.json')).read_bytes())

    def replace(self, value, role='gateway'):
        self.replace_configuration('mk8.email', role + '.json', encoded(value))

    def refused(self, value, role='gateway', message='.'):
        self.replace(value, role); observer = Mock(); original = self.n['email_credential_observe']
        self.n['email_credential_observe'] = observer
        try:
            before = self.snapshot()
            with self.assertRaisesRegex(ValueError, message): self.candidate()
            observer.assert_not_called(); self.assertEqual(before, self.snapshot())
        finally:
            self.n['email_credential_observe'] = original

    def test_distinct_accounts_and_state_leaves_have_no_shared_or_ancestor_owner(self):
        before = self.snapshot(); value = self.candidate()
        units = {row['file']: row['content'] for row in value['files']}
        leaves = []
        for role in ('worker', 'gateway'):
            unit = units['systemd/mk8-email-' + role + '.service']
            self.assertIn('User=mk8email-' + role + '\n', unit)
            self.assertIn('Group=mk8email-' + role + '\n', unit)
            self.assertNotIn('User=mk8email\n', unit); self.assertNotIn('Group=mk8email\n', unit)
            state = [line.split('=', 1)[1] for line in unit.splitlines() if line.startswith('StateDirectory=')]
            self.assertEqual(state, ['mk8.email/' + role]); leaves.extend(state)
            self.assertIn('StateDirectoryMode=0700\n', unit)
            self.assertNotIn('RuntimeDirectory=', unit)
            self.assertIn('# Inactive candidate; runtime unproven.\n', unit)
        self.assertEqual(len(set(leaves)), 2)
        self.assertFalse(any(a.startswith(b + '/') for a in leaves for b in leaves if a != b))
        self.assertEqual(before, self.snapshot()); self.assertTrue(all(flag is False for flag in value['authority'].values()))

    def test_gateway_declared_paths_are_inside_its_exact_state_leaf_and_bound_to_original_bytes(self):
        value = self.candidate(); admin = self.control()['Admin']
        self.assertEqual(admin['DataProtectionKeyPath'], '/var/lib/mk8.email/gateway/data-protection')
        self.assertEqual(admin['AuditLogPath'], '/var/lib/mk8.email/gateway/audit/admin.jsonl')
        self.assertEqual(admin['HealthStatusPath'], '/var/lib/mk8.email/gateway/health/status.json')
        row = next(row for row in value['configuration'] if row['file'] == '/etc/mk8.email/gateway.json')
        data = (self.root / row['file'][1:]).read_bytes()
        self.assertEqual(row['bytes'], len(data)); self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
        self.assertFalse(value['authority']['service_accounts_provisioned'])
        self.assertFalse(value['authority']['configuration_matches_network_and_storage_policy'])

    def test_role_specific_credential_sets_and_closed_dns_runtime_ownership_are_preserved(self):
        value = self.candidate(); units = {row['file']: row['content'] for row in value['files']}
        self.assertEqual([len(row['inputs']) for row in value['email_credentials']], [8, 7])
        for row in value['email_credentials']:
            unit = units['systemd/' + row['unit']]
            self.assertEqual([line for line in unit.splitlines() if line.startswith('LoadCredential=')],
                             ['LoadCredential=' + item['id'] + ':' + item['source'] for item in row['inputs']])
        self.assertIn('RuntimeDirectory=mk8.dns/controller\n', units['systemd/mk8-dns-controller.service'])
        self.assertIn('RuntimeDirectory=mk8.dns/authoritative-replica\n', units['systemd/mk8-dns-authoritative-replica.service'])
        self.assertNotIn('RuntimeDirectory=', units['systemd/mk8-drava-gateway.service'])
        self.assertEqual(len(value['authority']), 27); self.assertTrue(all(flag is False for flag in value['authority'].values()))

    def test_missing_null_wrong_case_or_unknown_admin_record_refuses_before_nested_observer(self):
        original = self.control()
        for kind in ('absent', 'null', 'case', 'extra'):
            with self.subTest(kind=kind):
                value = copy.deepcopy(original)
                if kind == 'absent': del value['Admin']
                elif kind == 'null': value['Admin'] = None
                elif kind == 'case': value['admin'] = value.pop('Admin')
                else: value['Admin']['Unknown'] = True
                self.refused(value)

    def test_worker_cannot_borrow_gateway_admin_declarations(self):
        original = self.control('worker')
        for admin in (None, {}, self.control()['Admin']):
            with self.subTest(admin=admin):
                value = copy.deepcopy(original); value['Admin'] = admin
                self.refused(value, 'worker', 'gateway-only')

    def test_every_persistence_path_rejects_relative_other_role_parent_and_decoded_controls(self):
        original = self.control()
        for field in ('DataProtectionKeyPath', 'AuditLogPath', 'HealthStatusPath'):
            for bad in ('relative', '/var/lib/mk8.email', '/var/lib/mk8.email/worker/secret',
                        '/var/lib/mk8.email/gateway/../escape', '%S/mk8.email/gateway', None, True,
                        '/var/lib/mk8.email/gateway/health/status.json\n'):
                with self.subTest(field=field, bad=bad):
                    value = copy.deepcopy(original); value['Admin'][field] = bad
                    self.refused(value, message='persistent paths')

    def test_all_three_paths_are_required_even_after_two_valid_fields(self):
        original = self.control()
        for field in ('DataProtectionKeyPath', 'AuditLogPath', 'HealthStatusPath'):
            with self.subTest(field=field):
                value = copy.deepcopy(original); del value['Admin'][field]; self.refused(value)

    def test_admin_networks_reject_wide_loopback_public_alias_duplicate_and_late_extra_rows(self):
        original = self.control()
        for networks in (None, [], {}, True, ['0.0.0.0/0'], ['192.168.0.0/16'], ['fc00::/7'],
                         ['127.0.0.1/32'], [str(net_fixture.ADMIN4), str(net_fixture.ADMIN4)],
                         [str(net_fixture.ADMIN4), str(net_fixture.PUBLIC6).split('::')[0] + '::/64'], [str(net_fixture.ADMIN4), None],
                         [str(net_fixture.ADMIN4), str(net_fixture.ADMIN6), '0.0.0.0/0']):
            with self.subTest(networks=networks):
                value = copy.deepcopy(original); value['Admin']['AllowedNetworks'] = networks
                self.refused(value, message='network declarations')

    def test_declared_ipv6_admin_is_optional_and_requires_its_manifest_entry(self):
        value = self.control(); value['Admin']['AllowedNetworks'] = [str(net_fixture.ADMIN4), str(net_fixture.ADMIN6)]
        self.replace(value); candidate = self.candidate()
        self.assertFalse(candidate['authority']['configuration_matches_network_and_storage_policy'])
        self.value['admin']['ipv6'] = None
        with self.assertRaisesRegex(ValueError, 'network declarations'): self.candidate()
        value['Admin']['AllowedNetworks'] = [str(net_fixture.ADMIN4)]; self.replace(value)
        self.assertEqual(len(self.candidate()['files']), 9)

    def test_admin_prefix_order_and_canonical_literal_spelling_are_required(self):
        original = self.control()
        for networks in ([str(net_fixture.ADMIN6), str(net_fixture.ADMIN4)], [((net_fixture.admin4(1)) + '/24')],
                         [((str(net_fixture.ADMIN4)) + ' ')], [str(net_fixture.ADMIN4), net_fixture.ADMIN6.network_address.exploded + '/64']):
            with self.subTest(networks=networks):
                value = copy.deepcopy(original); value['Admin']['AllowedNetworks'] = networks; self.refused(value)

    def test_session_values_are_exact_bounded_integers_and_omission_retains_source_default(self):
        original = self.control()
        for bad in (True, False, 4, 481, 30.0, None, '30'):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['Admin']['SessionMinutes'] = bad; self.refused(value)
        for minutes in (5, 480):
            value = copy.deepcopy(original); value['Admin']['SessionMinutes'] = minutes; self.replace(value); self.candidate()
        self.replace(original); self.assertEqual(len(self.candidate()['files']), 9)

    def test_ipv4_ipv6_and_dual_public_variants_keep_lan_only_admin_and_distinct_state_owners(self):
        for ipv4, ipv6 in ((net_fixture.nat4(), None), (None, net_fixture.PUBLIC6), (net_fixture.nat4(), net_fixture.PUBLIC6)):
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                self.value['public'].update(ipv4=ipv4, ipv6=ipv6); self.value['admin']['ipv6'] = None
                units = {row['file']: row['content'] for row in self.candidate()['files']}
                self.assertIn('StateDirectory=mk8.email/gateway\n', units['systemd/mk8-email-gateway.service'])
                self.assertIn('StateDirectory=mk8.email/worker\n', units['systemd/mk8-email-worker.service'])

    def test_whole_emitted_role_candidate_preserves_inputs_and_withholds_runtime_authority(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout); units = {row['file']: row['content'] for row in value['files']}
        self.assertIn('User=mk8email-worker\n', units['systemd/mk8-email-worker.service'])
        self.assertIn('User=mk8email-gateway\n', units['systemd/mk8-email-gateway.service'])
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertEqual(before, self.snapshot())

    def test_whole_emitted_late_wide_admin_prefix_refuses_specific_no_json_without_mutation(self):
        value = self.control(); value['Admin']['AllowedNetworks'].append('0.0.0.0/0'); self.replace(value)
        self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n'); self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()

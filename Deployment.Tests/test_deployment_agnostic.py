"""Caller-bound network/zone/node declarations, never tracked site defaults."""

import copy
import hashlib
import ipaddress
import json
from unittest.mock import Mock

import deployment_fixture as vectors
import test_deployment_services as services
from test_deployment_policy import encoded, library, manifest
from test_deployment_releases import ReleaseFixture


class DeploymentAgnosticTests(ReleaseFixture):
    candidate = services.DeploymentApplicationServiceTests.candidate
    replace_configuration = services.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = services.DeploymentApplicationServiceTests.run_emitted

    def reject_manifest(self, value):
        producer = Mock(wraps=self.n['bundle'])
        with self.assertRaises((ValueError, TypeError)):
            self.n['deployment_bundle'](encoded(value), producer)
        producer.assert_not_called()

    def test_manifest_prefixes_bind_same_ssh_listener_and_firewall_rows(self):
        result = self.n['deployment_bundle'](encoded(self.value), self.n['bundle']); plan = result['manifest']
        self.assertEqual([row['prefix'] for row in plan['admin']],
                         [self.value['admin'][name]['prefix'] for name in ('ipv4', 'ipv6')])
        self.assertTrue(all(v is False for v in result['authority'].values()))

    def test_unrelated_private_network_and_router_are_accepted_as_declarations(self):
        value = manifest(); network = vectors.SECOND4
        value['admin']['ipv4'].update(prefix=str(network), address=str(network.network_address + 11), routers=[str(network.network_address + 2)])
        result = self.n['deployment_bundle'](encoded(value), self.n['bundle'])
        self.assertEqual(result['manifest']['admin'][0]['prefix'], str(network))
        self.assertIn('saddr ' + str(network), result['files'][1]['content'])
        self.assertNotIn(str(vectors.ADMIN4), result['files'][0]['content'])

    def test_explicit_ipv4_minimum_host_network_keeps_two_distinct_usable_hosts(self):
        value = manifest(False); network = ipaddress.ip_network((int(vectors.ADMIN4.network_address), 30))
        value['admin']['ipv4'].update(prefix=str(network), address=str(network.network_address + 1), routers=[str(network.network_address + 2)])
        self.assertEqual(self.n['deployment_manifest'](value)['admin'][0]['prefix'], str(network))

    def test_explicit_ipv6_smallest_supported_prefix_is_family_correct(self):
        value = manifest(); network = ipaddress.ip_network((int(vectors.ADMIN6.network_address), 126))
        value['admin']['ipv6'].update(prefix=str(network), address=str(network.network_address + 1), routers=[str(network.network_address + 2)])
        self.assertEqual(self.n['deployment_manifest'](value)['admin'][1]['prefix'], str(network))

    def test_missing_null_bool_object_or_array_prefixes_have_no_default(self):
        for family in ('ipv4', 'ipv6'):
            for prefix in (None, True, {}, [], ''):
                value = manifest(); value['admin'][family]['prefix'] = prefix; self.reject_manifest(value)
            value = manifest(); del value['admin'][family]['prefix']; self.reject_manifest(value)

    def test_ipv4_prefix_family_private_bounds_and_umbrella_refusals(self):
        for prefix in ('0.0.0.0/0', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.1/32',
                       '192.0.2.0/24', str(vectors.ADMIN6), vectors.admin4(0) + '/31', vectors.admin4(0) + '/32'):
            value = manifest(); value['admin']['ipv4']['prefix'] = prefix; self.reject_manifest(value)

    def test_ipv6_prefix_family_local_bit_bounds_and_umbrella_refusals(self):
        for prefix in ('::/0', 'fc00::/7', 'fc00::/64', 'fd00::/8', '2001:db8::/64', str(vectors.ADMIN4),
                       vectors.admin6(0) + '/63', vectors.admin6(0) + '/127', vectors.admin6(0) + '/128'):
            value = manifest(); value['admin']['ipv6']['prefix'] = prefix; self.reject_manifest(value)

    def test_prefix_host_bits_netmask_expansion_case_and_decoded_text_refuse(self):
        for family, values in (('ipv4', (vectors.admin4(1) + '/24', vectors.admin4(0) + '/255.255.255.0', str(vectors.ADMIN4) + ' ')),
                               ('ipv6', (vectors.admin6(1) + '/64', str(vectors.ADMIN6).upper(), vectors.ADMIN6.network_address.exploded + '/64', str(vectors.ADMIN6) + '%test'))):
            for prefix in values:
                value = manifest(); value['admin'][family]['prefix'] = prefix; self.reject_manifest(value)
        for control in ('\naccept', '\t', '\x00', '\u0085', '\u2028'):
            value = manifest(); value['admin']['ipv6']['prefix'] += control; self.reject_manifest(value)

    def test_changed_prefix_cannot_borrow_old_listener_or_router_membership(self):
        value = manifest(); value['admin']['ipv4']['prefix'] = str(vectors.SECOND4); self.reject_manifest(value)
        value['admin']['ipv4']['address'] = vectors.second4(10); self.reject_manifest(value)

    def test_public_nat_overlap_uses_actual_supplied_admin_network(self):
        value = manifest(); value['admin']['ipv4'].update(prefix=str(vectors.NAT4), address=vectors.nat4(10), routers=[vectors.nat4(1)])
        self.reject_manifest(value)
        value['public']['ipv4'] = vectors.admin4(20)
        result = self.n['deployment_manifest'](value)
        self.assertEqual(result['admin'][0]['prefix'], str(vectors.NAT4))
        self.assertEqual(result['public'][0]['address'], vectors.admin4(20))

    def test_null_admin_ipv6_stays_independent_from_explicit_public_gua(self):
        value = manifest(False); value['public']['ipv6'] = vectors.PUBLIC6
        result = self.n['deployment_manifest'](value); self.assertEqual(len(result['admin']), 1)
        self.assertEqual(result['public'][1]['address'], vectors.PUBLIC6)

    def test_all_four_domains_and_zone_are_caller_supplied_reserved_test_names(self):
        value = manifest(); value['dns_zone'] = 'another.invalid'
        value['domains'] = {app: app.split('.')[1] + '.another.invalid' for app in self.n['DEP_APPS']}
        result = self.n['deployment_bundle'](encoded(value), self.n['bundle'])
        self.assertEqual(result['manifest']['domains'], value['domains'])
        self.assertNotIn('example.test', json.dumps(result))

    def test_caller_domains_do_not_accept_mismatched_zone_duplicates_or_controls(self):
        for zone in ('other.invalid', 'Example.test', 'example.test.', 'example.test\n'):
            value = manifest(); value['dns_zone'] = zone; self.reject_manifest(value)
        value = manifest(); value['domains']['mk8.dns'] = value['domains']['mk8.email']; self.reject_manifest(value)

    def test_dns_node_ids_are_required_unique_bounded_and_injection_safe(self):
        for change in ('missing', 'null', 'duplicate', 'extra', 'case', 'space', 'long', 'newline'):
            value = manifest()
            if change == 'missing': del value['dns_nodes']
            elif change == 'null': value['dns_nodes'] = None
            elif change == 'duplicate': value['dns_nodes']['controller'] = value['dns_nodes']['authoritative-replica']
            elif change == 'extra': value['dns_nodes']['gateway'] = 'extra-node'
            else: value['dns_nodes']['controller'] = {'case':'Upper','space':'node value','long':'x'*64,'newline':'node\nExecStart=bad'}[change]
            self.reject_manifest(value)

    def replace_email_network(self, prefixes):
        path = self.root / 'etc/mk8.email/gateway.json'; value = json.loads(path.read_bytes())
        value['Admin']['AllowedNetworks'] = prefixes
        self.replace_configuration('mk8.email', 'gateway.json', encoded(value))

    def test_email_admin_must_follow_new_explicit_prefix_without_cached_site_values(self):
        self.value['admin']['ipv4'].update(prefix=str(vectors.SECOND4), address=vectors.second4(10), routers=[vectors.second4(1)])
        with self.assertRaisesRegex(ValueError, 'network declarations'): self.candidate()
        self.replace_email_network([str(vectors.SECOND4)])
        result = self.candidate()
        self.assertEqual(self.n['deployment_manifest'](self.value)['admin'][0]['prefix'], str(vectors.SECOND4))
        self.assertIn('/etc/mk8.email/gateway.json', [row['file'] for row in result['configuration']])

    def test_dns_controller_replica_configs_and_cli_bind_explicit_node_ids(self):
        self.value['dns_nodes'] = {'controller':'controller-other','authoritative-replica':'replica-other'}
        with self.assertRaisesRegex(ValueError, 'target-node'): self.candidate()
        for leaf in ('control-plane.json','authority.json'):
            value = json.loads((self.root/'etc/mk8.dns'/leaf).read_bytes());value['TargetNode']='replica-other'
            self.replace_configuration('mk8.dns',leaf,encoded(value))
        units = {row['file']:row['content'] for row in self.candidate()['files']}
        self.assertIn('--node controller-other --role controller',units['systemd/mk8-dns-controller.service'])
        self.assertIn('--node replica-other --role authoritative-replica',units['systemd/mk8-dns-authoritative-replica.service'])

    def test_mismatched_late_replica_node_cannot_borrow_valid_controller_record(self):
        value=json.loads((self.root/'etc/mk8.dns/authority.json').read_bytes());value['TargetNode']='another-node'
        self.replace_configuration('mk8.dns','authority.json',encoded(value))
        with self.assertRaisesRegex(ValueError,'target-node'):self.candidate()

    def test_whole_emitted_alternate_prefix_and_zone_bind_original_configuration(self):
        self.value['admin']['ipv4'].update(prefix=str(vectors.SECOND4),address=vectors.second4(10),routers=[vectors.second4(1)])
        self.value['dns_zone']='another.invalid';self.value['domains']={app:app.split('.')[1]+'.another.invalid' for app in self.n['DEP_APPS']}
        self.replace_email_network([str(vectors.SECOND4)])
        for role in ('worker','gateway'):
            value=json.loads((self.root/'etc/mk8.email'/(''+role+'.json')).read_bytes());value['Smtp']['Hostname']=self.value['domains']['mk8.email']
            self.replace_configuration('mk8.email',role+'.json',encoded(value))
        for leaf in ('control-plane.json','authority.json'):
            value=json.loads((self.root/'etc/mk8.dns'/leaf).read_bytes());value['Zones'][0]['Origin']='another.invalid.'
            if 'Grants' in value:value['Grants'][0]['Origin']='another.invalid.'
            self.replace_configuration('mk8.dns',leaf,encoded(value))
        result=self.run_emitted();self.assertEqual(result.returncode,0,result.stderr)
        output=json.loads(result.stdout)
        candidate=self.n['deployment_bundle'](encoded(self.value),self.n['bundle'])
        self.assertEqual(candidate['manifest']['admin'][0]['prefix'],str(vectors.SECOND4))
        self.assertEqual(candidate['manifest']['dns_zone'],'another.invalid')
        raw=json.dumps(candidate,sort_keys=True,separators=(',',':')).encode('ascii')
        self.assertEqual(output['deployment_candidate_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertTrue(all(flag is False for flag in output['authority'].values()))

    def test_whole_emitted_missing_prefix_refuses_specific75_without_json(self):
        del self.value['admin']['ipv4']['prefix']
        result=self.run_emitted();self.assertEqual(result.returncode,75);self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'Application service candidate refused\n')

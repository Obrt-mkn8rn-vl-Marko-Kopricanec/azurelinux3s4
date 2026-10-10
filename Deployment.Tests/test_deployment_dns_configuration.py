"""Complete typed DNS declarations; no serializer, crypto, database or app run."""

import deployment_fixture as net_fixture

import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ReleaseFixture
import test_deployment_services as service_fixture


class DNSControlConfigurationTests(ReleaseFixture):
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = service_fixture.DeploymentApplicationServiceTests.run_emitted

    def control(self, leaf='control-plane.json'):
        return json.loads((self.root / 'etc/mk8.dns' / leaf).read_bytes())

    def replace(self, value, leaf='control-plane.json'):
        self.replace_configuration('mk8.dns', leaf, encoded(value))

    def refuse(self, value, leaf='control-plane.json'):
        self.replace(value, leaf)
        before = self.snapshot()
        with self.assertRaises((ValueError, TypeError)): self.candidate()
        self.assertEqual(before, self.snapshot())

    def grant_variant(self, profile, actions, scopes):
        value = self.control(); grant = value['Grants'][0]
        grant.update(Profile=profile, Actions=actions, RecordScopes=scopes)
        return value

    def signing_variant(self):
        value = self.control(); zone = value['Zones'][0]
        name = 'zone-' + zone['ZoneId'] + '.pk8'
        zone['SigningKeyFile'] = '/run/mk8.dns/controller/inputs/' + name
        path = self.root / 'etc/mk8.dns/controller' / name
        path.write_bytes(b'finite binary signing input, not a PKCS8 proof'); path.chmod(0o600)
        return value

    def test_complete_pair_binds_original_bytes_and_withholds_every_authority(self):
        before = self.snapshot(); value = self.candidate(); rows = value['dns_control_configuration']
        self.assertEqual([row['role'] for row in rows], ['controller', 'authoritative-replica'])
        self.assertEqual([row['grant_count'] for row in rows], [1, 0])
        self.assertEqual(rows[0]['zones'], rows[1]['zones'])
        for row, leaf in zip(rows, ('control-plane.json', 'authority.json')):
            data = (self.root / 'etc/mk8.dns' / leaf).read_bytes()
            self.assertEqual((row['original_bytes'], row['original_sha256']), (len(data), hashlib.sha256(data).hexdigest()))
            self.assertEqual(len(row['authority']), 16); self.assertTrue(all(flag is False for flag in row['authority'].values()))
            self.assertEqual(row['target_node_declaration'], self.value['dns_nodes']['authoritative-replica'])
        self.assertEqual(len(value['authority']), 27); self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertEqual(before, self.snapshot())

    def test_valid_pair_is_independent_of_public_family_and_missing_admin_ipv6(self):
        for ipv4, ipv6 in ((net_fixture.nat4(), None), (None, net_fixture.PUBLIC6), (net_fixture.nat4(), net_fixture.PUBLIC6)):
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                self.value['public'].update(ipv4=ipv4, ipv6=ipv6); self.value['admin']['ipv6'] = None
                value = self.candidate(); self.assertEqual(len(value['dns_control_configuration']), 2)
                self.assertTrue(all(flag is False for row in value['dns_control_configuration'] for flag in row['authority'].values()))

    def test_missing_unknown_and_wrong_case_control_fields_refuse_before_credential_factory(self):
        original = self.control(); observer = Mock(); self.n['dns_credential_observe'] = observer
        for changed in ('missing', 'unknown', 'case'):
            with self.subTest(changed=changed):
                value = copy.deepcopy(original)
                if changed == 'missing': del value['Epoch']
                elif changed == 'unknown': value['Unknown'] = True
                else: value['epoch'] = value.pop('Epoch')
                self.refuse(value)
        observer.assert_not_called()

    def test_nonempty_canonical_epoch_zone_and_tenant_identity_profiles(self):
        original = self.control()
        for bad in (None, True, 1, [], '00000000-0000-0000-0000-000000000000', '22222222222222222222222222222222', 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'):
            for field in ('Epoch', 'ZoneId', 'TenantId'):
                with self.subTest(bad=bad, field=field):
                    value = copy.deepcopy(original)
                    if field == 'Epoch': value[field] = bad
                    elif field == 'ZoneId': value['Zones'][0][field] = bad
                    else: value['Grants'][0][field] = bad
                    self.refuse(value)

    def test_target_must_match_the_declared_replica_unit_node(self):
        original = self.control()
        for bad in ('test-controller', 'other-replica', None, [], True, self.value['dns_nodes']['authoritative-replica'] + '\n'):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['TargetNode'] = bad; self.refuse(value)

    def test_complete_zone_set_and_pair_epoch_correspondence_refuse(self):
        original = self.control('authority.json')
        for change in ('epoch', 'extra', 'identity', 'origin'):
            with self.subTest(change=change):
                value = copy.deepcopy(original)
                if change == 'epoch': value['Epoch'] = '44444444-4444-4444-4444-444444444444'
                elif change == 'extra': value['Zones'].append({'ZoneId': '44444444-4444-4444-4444-444444444444', 'Origin': 'other.example.test.'})
                elif change == 'identity': value['Zones'][0]['ZoneId'] = '44444444-4444-4444-4444-444444444444'
                else: value['Zones'][0]['Origin'] = 'other.test.'
                self.refuse(value, 'authority.json')

    def test_late_invalid_zone_and_duplicate_origin_cannot_borrow_early_valid_data(self):
        original = self.control()
        for later in ({'ZoneId': '44444444-4444-4444-4444-444444444444', 'Origin': 'bad'},
                      {'ZoneId': '44444444-4444-4444-4444-444444444444', 'Origin': 'example.test.'},
                      {'ZoneId': '44444444-4444-4444-4444-444444444444', 'Origin': 'other.example.test.', 'Unknown': 1}):
            with self.subTest(later=later):
                value = copy.deepcopy(original); value['Zones'].append(later); self.refuse(value)

    def test_uint_fields_reject_bool_float_negative_and_overflow(self):
        original = self.control()
        for bad in (True, False, 1.0, -1, 4294967296, None):
            for field in ('SigningScanSeconds', 'SignatureLifetimeSeconds', 'DnskeyTtl'):
                with self.subTest(bad=bad, field=field):
                    value = copy.deepcopy(original)
                    if field == 'SigningScanSeconds': value[field] = bad
                    else: value['Zones'][0][field] = bad
                    self.refuse(value)

    def test_replica_omitted_null_and_empty_grants_are_distinct_valid_declarations(self):
        original = self.control('authority.json')
        for grants in (None, []):
            with self.subTest(grants=grants):
                value = copy.deepcopy(original); value['Grants'] = grants; self.replace(value, 'authority.json')
                self.assertEqual(self.candidate()['dns_control_configuration'][1]['grant_count'], 0)
        for bad in (False, {}, [original], '[]'):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['Grants'] = bad; self.refuse(value, 'authority.json')

    def test_controller_requires_bounded_complete_grants(self):
        original = self.control()
        for bad in (None, [], {}, True, original['Grants'] * 65):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['Grants'] = bad; self.refuse(value)

    def test_grant_scope_actor_and_complete_fields_refuse_unsupported_values(self):
        original = self.control()
        for field, bad in (('Origin', 'other.example.test.'), ('Actor', ' '), ('Actor', 'a\nsecret'), ('Actor', 'a' * 129),
                           ('TenantId', None), ('CredentialHash', None), ('Unknown', True)):
            with self.subTest(field=field, bad=bad):
                value = copy.deepcopy(original); value['Grants'][0][field] = bad; self.refuse(value)
        value = copy.deepcopy(original); del value['Grants'][0]['Actor']; self.refuse(value)

    def test_duplicate_scoped_actor_and_credential_hash_are_checked_separately(self):
        original = self.control()
        for duplicate in ('actor', 'hash'):
            with self.subTest(duplicate=duplicate):
                value = copy.deepcopy(original); grant = copy.deepcopy(value['Grants'][0])
                if duplicate == 'actor': grant['CredentialHash'] = base64.b64encode(b'B' * 32).decode('ascii')
                else: grant['Actor'] = 'other-actor'
                value['Grants'].append(grant); self.refuse(value)

    def test_hash_requires_exact_canonical_32_byte_base64_without_exposing_it(self):
        original = self.control()
        for bad in (base64.b64encode(b'x' * 31).decode(), base64.b64encode(b'x' * 33).decode(), 'A' * 42 + 'B=',
                    original['Grants'][0]['CredentialHash'] + '\n', [], 32):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['Grants'][0]['CredentialHash'] = bad; self.refuse(value)
        self.replace(original)
        self.assertNotIn(original['Grants'][0]['CredentialHash'], json.dumps(self.candidate()))

    def test_supported_zone_records_and_acme_profiles_remain_unselected(self):
        variants = [('zone', None, None, 0), ('records', ['patch', 'read', 'status'], [{'Owner': 'www.example.test.', 'Type': 1}], 1),
                    ('acme', ['patch', 'status'], [{'Owner': '_acme-challenge.example.test.', 'Type': 16}], 1)]
        for profile, actions, scopes, count in variants:
            with self.subTest(profile=profile):
                self.replace(self.grant_variant(profile, actions, scopes))
                row = self.candidate()['dns_control_configuration'][0]
                self.assertEqual(row['record_scope_count'], count); self.assertFalse(row['authority']['request_actions_authorized'])
                self.assertFalse(row['authority']['record_scope_authorized'])

    def test_profiles_and_actions_refuse_duplicates_or_unprofiled_authority(self):
        for profile, actions, scopes in (('unknown', ['read'], []), (None, ['read'], []), ('zone', ['read', 'read'], []),
                                       ('zone', ['READ'], []), ('zone', [], []), ('zone', ['read'], [{}]),
                                       ('records', ['edit'], [{'Owner': 'www.example.test.', 'Type': 1}]), ('records', None, [])):
            with self.subTest(profile=profile, actions=actions): self.refuse(self.grant_variant(profile, actions, scopes))

    def test_record_type_and_name_boundaries_refuse_scope_expansion(self):
        for kind in (0, 6, 41, 249, 255, 65536, -1, True, 1.0):
            with self.subTest(kind=kind): self.refuse(self.grant_variant('records', ['read'], [{'Owner': 'www.example.test.', 'Type': kind}]))
        for owner in ('www.other.test.', 'www.badexample.test.', 'WWW.example.test.', 'www.example.test', '*.example.test.', 'www\\046example.test.'):
            with self.subTest(owner=owner): self.refuse(self.grant_variant('records', ['read'], [{'Owner': owner, 'Type': 1}]))
        for scope in ({'Owner': 'www.example.test.', 'Type': 16}, {'Owner': '_acme-challenge.example.test.', 'Type': 1}):
            with self.subTest(scope=scope): self.refuse(self.grant_variant('acme', ['patch'], [scope]))

    def test_late_and_duplicate_record_scopes_and_complete_bounds_refuse(self):
        first = {'Owner': 'www.example.test.', 'Type': 1}
        for scopes in ([first, first], [first, {'Owner': 'bad', 'Type': 1}], [first, {'Owner': 'other.example.test.', 'Type': 1, 'Unknown': 0}], [first] * 65):
            with self.subTest(scopes=scopes): self.refuse(self.grant_variant('records', ['read'], scopes))

    def test_expiry_calendar_literals_preserve_past_and_fraction_without_freshness_claim(self):
        original = self.control()
        for expiry in ('2000-01-01T00:00:00Z', '2030-01-01T00:00:00.1234567Z'):
            with self.subTest(expiry=expiry):
                value = copy.deepcopy(original); value['Grants'][0]['Expires'] = expiry; self.replace(value)
                before = (self.root / 'etc/mk8.dns/control-plane.json').read_bytes()
                row = self.candidate()['dns_control_configuration'][0]
                self.assertFalse(row['authority']['grant_expiry_current'])
                self.assertEqual(row['original_sha256'], hashlib.sha256(before).hexdigest())
                self.assertEqual((self.root / 'etc/mk8.dns/control-plane.json').read_bytes(), before)

    def test_invalid_or_unsupported_expiry_text_refuses(self):
        original = self.control()
        for expiry in ('2026-02-30T00:00:00Z', '0000-01-01T00:00:00Z', '2030-01-01T00:00:60Z', '2030-01-01T00:00:00+01:00',
                       '2030-01-01T00:00:00Z\n', '2030-01-01T00:00:00.12345678Z', None, 2030):
            with self.subTest(expiry=expiry):
                value = copy.deepcopy(original); value['Grants'][0]['Expires'] = expiry; self.refuse(value)

    def test_signing_lifetime_margin_scan_and_unsigned_policy_boundaries(self):
        original = self.signing_variant()
        self.replace(original); self.assertEqual(self.candidate()['dns_control_configuration'][0]['private_signing_reference_count'], 1)
        for field, bad in (('SignatureLifetimeSeconds', 3599), ('SignatureLifetimeSeconds', 2592001), ('RenewBeforeSeconds', 59),
                           ('RenewBeforeSeconds', 604741), ('RenewBeforeSeconds', False), ('SigningScanSeconds', 0), ('SigningScanSeconds', 301)):
            with self.subTest(field=field, bad=bad):
                value = copy.deepcopy(original)
                if field == 'SigningScanSeconds': value[field] = bad
                else: value['Zones'][0][field] = bad
                self.refuse(value)
        value = copy.deepcopy(original); value['Zones'][0]['RenewBeforeSeconds'] = 60; value['SigningScanSeconds'] = 31; self.refuse(value)
        value = copy.deepcopy(original); del value['Zones'][0]['SigningKeyFile']; value['Zones'][0]['DnskeyTtl'] = 0; self.refuse(value)

    def test_entire_emitted_control_candidate_retains_raw_bindings_and_false_authorities(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout); self.assertEqual(len(value['dns_control_configuration']), 2)
        for row in value['dns_control_configuration']:
            self.assertTrue(all(flag is False for flag in row['authority'].values()))
        self.assertEqual(before, self.snapshot())

    def test_entire_emitted_late_bad_grant_refuses_without_json_or_mutation(self):
        value = self.control(); later = copy.deepcopy(value['Grants'][0]); later.update(Actor='later', CredentialHash=base64.b64encode(b'B' * 32).decode())
        later['RecordScopes'] = [{'Owner': 'www.example.test.', 'Type': 1}]
        value['Grants'].append(later); self.replace(value)
        self.manifest_file.write_bytes(encoded(self.value))
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n'); self.assertEqual(before, self.snapshot())

    def test_missing_raw_configuration_cannot_borrow_old_positive_declaration(self):
        self.n['STALE_DNS_CONTROL_OBSERVATION'] = self.candidate()['dns_control_configuration']
        (self.root / 'etc/mk8.dns/authority.json').unlink()
        before = self.snapshot()
        with self.assertRaises(FileNotFoundError): self.candidate()
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__': unittest.main()

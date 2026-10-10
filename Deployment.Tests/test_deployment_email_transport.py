"""Original Email transport declarations, independent budget controls and private IO."""

import collections
import copy
import hashlib
import json
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ReleaseFixture
import test_deployment_services as service_fixture


class EmailTransportTests(ReleaseFixture):
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = service_fixture.DeploymentApplicationServiceTests.run_emitted

    def role(self, role='worker'):
        return json.loads((self.root / 'etc/mk8.email' / (role + '.json')).read_bytes())

    def replace(self, role, value):
        self.replace_configuration('mk8.email', role + '.json', encoded(value))

    def plan(self, value):
        return self.n['email_transport_plan'](encoded(value))

    def observe(self):
        return self.n['email_transport_observe']({role + '.json':
            (self.root / 'etc/mk8.email' / (role + '.json')).read_bytes() for role in ('worker', 'gateway')})

    def refused(self, role, value, message='Email'):
        self.replace(role, value); original = self.n['email_credential_observe']
        observer = Mock(side_effect=AssertionError('nested read forbidden'))
        self.n['email_credential_observe'] = observer
        try:
            before = self.snapshot()
            with self.assertRaisesRegex(ValueError, message): self.candidate()
            observer.assert_not_called(); self.assertEqual(before, self.snapshot())
        finally:
            self.n['email_credential_observe'] = original

    def test_default_declarations_bind_both_original_configuration_bytes_and_false_authorities(self):
        before = self.snapshot(); value = self.candidate()
        observation = self.observe()
        self.assertEqual([item['role'] for item in observation['roles']], ['worker', 'gateway'])
        for item in observation['roles']:
            self.assertEqual(item['payload_bytes'], 67108864)
            self.assertEqual(item['minimum_payload_bytes'], 66928812)
            self.assertEqual(len(item['declaration_sha256']), 64)
            source = self.root / 'etc/mk8.email' / (item['role'] + '.json')
            original = next(x for x in value['configuration'] if x['file'] == '/etc/mk8.email/' + source.name)
            self.assertEqual(original['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(len(observation['authority']), 9)
        self.assertTrue(all(flag is False for flag in observation['authority'].values()))
        self.assertEqual(before, self.snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_selected_record_null_alias_unknown_and_late_nonobject_refuse_before_nested_reads(self):
        original = self.role('gateway')
        for record in ('Database', 'Messaging', 'ObjectStorage', 'Limits', 'Jmap', 'Dav'):
            for bad in (None, [], {'LateUnknown': 1}):
                with self.subTest(record=record, bad=bad):
                    value = copy.deepcopy(original); value[record] = bad
                    self.refused('gateway', value, 'canonical Email')

    def test_database_endpoint_refuses_remote_list_scope_alias_and_controls(self):
        original = self.role()
        for host in ('192.168.90.1', 'example.test', '127.1', '::1%eth0', 'localhost\n', '', None, True, ['localhost']):
            with self.subTest(host=host):
                value = copy.deepcopy(original); value['Database']['Host'] = host
                self.refused('worker', value, 'PostgreSQL endpoint')

    def test_all_supported_loopback_literals_and_distinct_safe_usernames_are_declarations_only(self):
        for host in ('localhost', '127.0.0.1', '::1'):
            for role in ('worker', 'gateway'):
                value = self.role(role); value['Database'].update(Host=host, Name='mail_90', Username='mail_' + role)
                self.replace(role, value)
            self.candidate(); observation = self.observe()
            self.assertFalse(observation['authority']['database_roles_and_schema_provisioned'])

    def test_database_ports_refuse_bool_float_null_and_out_of_range(self):
        original = self.role()
        for port in (True, False, 0, 65536, 5432.0, None, '5432'):
            with self.subTest(port=port):
                value = copy.deepcopy(original); value['Database']['Port'] = port
                self.refused('worker', value, 'integer')

    def test_database_identifiers_refuse_decoded_text_and_width_overflow(self):
        original = self.role()
        for key in ('Name', 'Username'):
            for bad in (None, True, '', 'Upper', 'mail-db', 'x; password=abc', 'x\n', 'a' * 64):
                with self.subTest(key=key, bad=bad):
                    value = copy.deepcopy(original); value['Database'][key] = bad
                    self.refused('worker', value, 'database identifiers')

    def test_gateway_late_database_mismatch_cannot_borrow_worker_admission(self):
        original = self.role('gateway')
        for field, bad in (('Host', '::1'), ('Port', 5433), ('Name', 'other')):
            value = copy.deepcopy(original); value['Database'][field] = bad
            self.refused('gateway', value, 'pair must share')

    def test_enabled_messaging_requires_actual_boolean_true(self):
        original = self.role()
        for enabled in (False, 1, 0, None, 'true'):
            value = copy.deepcopy(original); value['Messaging']['Enabled'] = enabled
            self.refused('worker', value)

    def test_every_messaging_integer_refuses_wrong_type_and_both_range_edges(self):
        original = self.role()
        limits = {'MaxPayloadBytes': (65536, 1073741824), 'InlinePayloadThresholdBytes': (0, 1048576),
                  'LeaseSeconds': (5, 3600), 'NotificationFallbackSeconds': (1, 300)}
        for field, (low, high) in limits.items():
            for bad in (True, None, float(low), low - 1, high + 1):
                value = copy.deepcopy(original); value['Messaging'][field] = bad
                self.refused('worker', value, 'integer')

    def test_worker_identifier_bounds_and_supported_source_alphabet_are_retained(self):
        original = self.role()
        for good in (None, 'worker90', 'a@site/worker:90', 'A' * 128):
            value = copy.deepcopy(original); value['Messaging']['WorkerId'] = good
            self.assertEqual(self.plan(value)['worker'], good)
        for bad in ('', '_first', 'a' * 129, 'a b', 'a\n', True, 90):
            value = copy.deepcopy(original); value['Messaging']['WorkerId'] = bad
            self.refused('worker', value, 'worker identifier')

    def test_blob_provider_and_container_refuse_unsupported_or_decoded_values(self):
        original = self.role()
        for field, values in (('Provider', ('Azure-Blob', 'file', None, True)),
                              ('ContainerName', ('ab', 'a' * 64, '-abc', 'abc-', 'a--b', 'Abc', 'a_b', 'a\nb', None))):
            for bad in values:
                value = copy.deepcopy(original); value['ObjectStorage'][field] = bad
                self.refused('worker', value, 'Blob provider and container')

    def test_blob_prefix_refuses_absolute_double_separator_whitespace_and_controls(self):
        original = self.role()
        for bad in ('/objects', 'a//b', 'a b', 'a\n', 'a\0', 'é', 'a' * 513, None, True):
            value = copy.deepcopy(original); value['ObjectStorage']['ObjectPrefix'] = bad
            self.refused('worker', value, 'Blob prefix')

    def test_empty_and_bounded_printable_blob_prefixes_preserve_original_bytes(self):
        original = self.role()
        for prefix in ('', 'mail90/objects/', 'a' * 512):
            value = copy.deepcopy(original); value['ObjectStorage']['ObjectPrefix'] = prefix
            raw = encoded(value); before = bytes(raw); plan = self.n['email_transport_plan'](raw)
            self.assertEqual(plan['blob'][2], prefix); self.assertEqual(raw, before)

    def test_blob_creation_flag_is_typed_but_confers_no_operation(self):
        original = self.role()
        for create in (False, True):
            value = copy.deepcopy(original); value['ObjectStorage']['CreateContainerIfMissing'] = create
            self.assertIs(self.plan(value)['blob'][3], create)
        for bad in (None, 0, 1, 'false'):
            value = copy.deepcopy(original); value['ObjectStorage']['CreateContainerIfMissing'] = bad
            self.refused('worker', value, 'boolean')

    def test_complete_blob_pair_mismatch_refuses_without_reading_nested_secrets(self):
        original = self.role('gateway')
        for field, bad in (('ContainerName', 'other-container'), ('ObjectPrefix', 'other/')):
            value = copy.deepcopy(original); value['ObjectStorage'][field] = bad
            self.refused('gateway', value, 'pair must share')

    def test_all_message_limits_are_true_bounded_ints_even_when_http_disabled(self):
        original = self.role(); original.update(Jmap={'EnableJmap': False}, Dav={'EnableDav': False})
        limits = {'MaxMessageSizeBytes': (65536, 2147483647), 'MaxRecipientsPerMessage': (1, 1000),
                  'ConnectionTimeoutSeconds': (10, 3600), 'MaxConnectionsPerIp': (1, 10000)}
        for field, (low, high) in limits.items():
            for bad in (True, None, float(low), low - 1, high + 1):
                value = copy.deepcopy(original); value['Limits'] = {field: bad}
                self.refused('worker', value, 'integer')

    def test_append_formula_preserves_distinct_integer_rounding_at_all_three_residues(self):
        original = self.role(); original.update(Jmap={'EnableJmap': False}, Dav={'EnableDav': False})
        for size, minimum in ((1048576, 2446678), (1048577, 2446679), (1048578, 2446680)):
            value = copy.deepcopy(original); value['Limits'] = {'MaxMessageSizeBytes': size}
            value['Messaging'].update(MaxPayloadBytes=minimum, InlinePayloadThresholdBytes=0)
            self.assertEqual(self.plan(value)['minimum_payload_bytes'], minimum)
            value['Messaging']['MaxPayloadBytes'] -= 1
            self.refused('worker', value, 'envelope budgets')

    def test_jmap_binary_upload_envelope_accepts_exact_boundary_and_refuses_one_byte_less(self):
        value = self.role(); value.update(Limits={'MaxMessageSizeBytes': 65536}, Dav={'EnableDav': False},
            Jmap={'MaxUploadSizeBytes': 1048576, 'MaxRequestSizeBytes': 65536})
        value['Messaging'].update(MaxPayloadBytes=1660248, InlinePayloadThresholdBytes=0)
        self.assertEqual(self.plan(value)['minimum_payload_bytes'], 1660248)
        value['Messaging']['MaxPayloadBytes'] -= 1; self.refused('worker', value, 'envelope budgets')

    def test_jmap_json_escape_envelope_accepts_exact_boundary_and_refuses_one_byte_less(self):
        value = self.role(); value.update(Limits={'MaxMessageSizeBytes': 65536}, Dav={'EnableDav': False},
            Jmap={'MaxUploadSizeBytes': 1048576, 'MaxRequestSizeBytes': 1000000})
        value['Messaging']['MaxPayloadBytes'] = 6262144
        self.assertEqual(self.plan(value)['minimum_payload_bytes'], 6262144)
        value['Messaging']['MaxPayloadBytes'] -= 1; self.refused('worker', value, 'envelope budgets')

    def test_dav_text_and_minimum_binary_body_envelopes_are_both_observed(self):
        original = self.role(); original.update(Limits={'MaxMessageSizeBytes': 65536}, Jmap={'EnableJmap': False})
        for size, minimum in ((65536, 1660248), (1000000, 6262144)):
            value = copy.deepcopy(original); value['Dav'] = {'MaxResourceSizeBytes': size}
            value['Messaging']['MaxPayloadBytes'] = minimum
            self.assertEqual(self.plan(value)['minimum_payload_bytes'], minimum)
            value['Messaging']['MaxPayloadBytes'] -= 1; self.refused('worker', value, 'envelope budgets')

    def test_late_jmap_and_dav_numeric_rows_refuse_even_after_valid_payload_and_database(self):
        original = self.role('gateway')
        for record, field, bad in (('Jmap', 'UploadRetentionHours', 169),
                ('Jmap', 'MaxObjectsInSet', True), ('Dav', 'MaxResourcesPerCollection', 1000001),
                ('Dav', 'MaxCollectionsPerUser', None), ('Jmap', 'MaxUnreferencedBlobBytesPerAccount', 9007199254740992)):
            value = copy.deepcopy(original); value[record] = {field: bad}
            self.refused('gateway', value, 'integer')

    def test_jmap_unreferenced_budget_cannot_be_lower_than_upload_or_message(self):
        value = self.role(); value['Jmap'] = {'MaxUnreferencedBlobBytesPerAccount': 49999999}
        self.refused('worker', value, 'blob retention')
        value = self.role(); value['Limits'] = {'MaxMessageSizeBytes': 100000001}
        self.refused('worker', value, 'blob retention')

    def test_disabled_http_features_do_not_add_enabled_envelope_budgets(self):
        value = self.role(); value.update(Jmap={'EnableJmap': False}, Dav={'EnableDav': False})
        value['Messaging']['MaxPayloadBytes'] = 15000000
        with self.assertRaisesRegex(ValueError, 'envelope budgets'): self.plan(value)
        value['Messaging']['MaxPayloadBytes'] = 15029590; self.plan(value)
        for record, key in (('Jmap', 'EnableJmap'), ('Dav', 'EnableDav')):
            changed = copy.deepcopy(value); changed[record][key] = True
            with self.assertRaisesRegex(ValueError, 'envelope budgets'): self.plan(changed)

    def test_whole_emitted_positive_preserves_sources_and_all_nested_false_authorities(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout); row = self.observe()
        self.assertEqual(len(row['roles']), 2)
        self.assertTrue(all(flag is False for flag in row['authority'].values()))
        self.assertFalse(value['authority']['application_configuration_schema_validated'])
        self.assertFalse(value['authority']['configuration_matches_network_and_storage_policy'])
        self.assertEqual(before, self.snapshot())

    def test_whole_emitted_late_gateway_budget_refuses_specific_no_json_without_mutation(self):
        value = self.role('gateway'); value['Messaging']['MaxPayloadBytes'] = 66928811
        self.replace('gateway', value); self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot()
        result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(before, self.snapshot())

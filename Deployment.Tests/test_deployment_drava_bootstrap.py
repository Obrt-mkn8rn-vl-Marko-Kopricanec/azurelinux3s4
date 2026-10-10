"""Original-byte Drava bootstrap declarations and explicit private delivery models."""

import collections
import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ROOT, ReleaseFixture
import test_deployment_services as drava_services


class DravaBootstrapTests(ReleaseFixture):
    replace_configuration = drava_services.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = drava_services.DeploymentApplicationServiceTests.run_emitted

    def candidate(self):
        return self.n['application_bundle'](encoded(self.value), self.n['bundle'])

    def role(self, role):
        return json.loads((self.root / 'etc/mk8.drava' / (role + '.json')).read_bytes())

    def set_role(self, role, value):
        self.replace_configuration('mk8.drava', role + '.json', encoded(value))

    def admit(self):
        captured = {role + '.json': (self.root / 'etc/mk8.drava' / (role + '.json')).read_bytes()
                    for role in ('application', 'gateway')}
        return self.n['drava_bootstrap_observe'](captured, self.n['deployment_manifest'](self.value))

    def refuse_before_nested(self, role, value, message='Drava'):
        self.set_role(role, value); reader = self.n['deployment_read']; nested = Mock(side_effect=AssertionError('nested read forbidden'))
        self.n['deployment_read'] = nested
        try:
            with self.assertRaisesRegex(ValueError, message): self.admit()
            nested.assert_not_called()
        finally:
            self.n['deployment_read'] = reader

    def test_complete_unenrolled_pair_binds_original_bootstraps_and_opaque_token(self):
        before = self.snapshot(); value = self.candidate()
        row = next(row for row in value['configuration'] if row['file'] == '/etc/mk8.drava/application.json')
        token = self.root / 'etc/mk8.drava/ipc-token.txt'; original = token.read_bytes()
        self.assertEqual(row['ipc_identity'], {'source': '/etc/mk8.drava/ipc-token.txt',
            'bytes': len(original), 'sha256': hashlib.sha256(original).hexdigest(), 'mode': '0600'})
        self.assertEqual(row['sha256'], hashlib.sha256((self.root / row['file'][1:]).read_bytes()).hexdigest())
        self.assertEqual(len(value['configuration']), 10)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertNotIn(original.decode().strip(), json.dumps(value))
        self.assertEqual(before, self.snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_state_socket_and_unit_directory_paths_match_both_original_consumers(self):
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        for role, field in (('application', 'listen'), ('gateway', 'application')):
            control = self.role(role); unit = units['systemd/mk8-drava-' + role + '.service']
            self.assertEqual(control['stateDirectory'], '/var/lib/mk8.drava/' + role)
            self.assertIn('StateDirectory=mk8.drava/' + role + '\nStateDirectoryMode=0700\n', unit)
            self.assertNotIn('StateDirectory=mk8.drava\n', unit)
            self.assertEqual(control[field]['unixSocketPath'], '/var/lib/mk8.drava/application/application.sock')
        self.assertEqual(str(Path(self.role('application')['listen']['unixSocketPath']).parent),
                         self.role('application')['stateDirectory'])
        self.assertNotIn('RuntimeDirectory=', units['systemd/mk8-drava-gateway.service'])

    def test_literal_per_role_credentials_share_only_the_fresh_protected_source(self):
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        for role, field in (('application', 'listen'), ('gateway', 'application')):
            unit = units['systemd/mk8-drava-' + role + '.service']
            self.assertIn('LoadCredential=ipc:/etc/mk8.drava/ipc-token.txt\n', unit)
            self.assertEqual(self.role(role)[field]['identityTokenPath'],
                             '/run/credentials/mk8-drava-' + role + '.service/ipc')
            self.assertNotIn('%d', self.role(role)[field]['identityTokenPath'])
        self.assertFalse(self.candidate()['authority']['runtime_credential_access_proven'])

    def test_unknown_wrong_case_null_and_nonobject_top_level_declarations_refuse(self):
        original = self.role('application')
        for kind in ('extra', 'case', 'null', 'list'):
            with self.subTest(kind=kind):
                value = copy.deepcopy(original)
                if kind == 'extra': value['lateUnknown'] = 1
                elif kind == 'case': value['SiteId'] = value.pop('siteId')
                elif kind == 'null': value = None
                else: value = []
                self.refuse_before_nested('application', value)

    def test_missing_empty_oversized_or_decoded_alias_identity_refuses(self):
        original = self.role('application')
        for value in (None, '', 'a' * 129, 'Upper', 'site\nname', 'site/name', True):
            with self.subTest(value=value):
                changed = copy.deepcopy(original); changed['nodeId'] = value
                self.refuse_before_nested('application', changed, 'manifest text')

    def test_pair_site_and_gateway_identity_mismatches_refuse_before_nested_read(self):
        original = self.role('gateway')
        for field in ('siteId', 'gatewayId'):
            changed = copy.deepcopy(original); changed[field] = 'another'
            self.refuse_before_nested('gateway', changed, 'pair identity')

    def test_schema_bool_float_null_and_wrong_version_refuse_before_nested_read(self):
        original = self.role('gateway')
        for value in (True, 1.0, None, 0, 2):
            with self.subTest(value=value):
                changed = copy.deepcopy(original); changed['schemaVersion'] = value
                self.refuse_before_nested('gateway', changed, 'integer')

    def test_state_shared_parent_wrong_leaf_alias_and_relative_paths_refuse(self):
        original = self.role('application')
        for value in ('/run/mk8.drava', '/var/lib/mk8.drava', '/var/lib/mk8.drava/gateway',
                      '/var/lib/mk8.drava/application/', '/var/lib/mk8.drava/application/../application', 'state', None):
            changed = copy.deepcopy(original); changed['stateDirectory'] = value
            self.refuse_before_nested('application', changed, 'persistent state')

    def test_runtime_socket_legacy_other_transports_and_late_unknown_endpoint_refuse(self):
        original = self.role('gateway')
        for field, value in (('unixSocketPath', '/run/mk8.drava/application.sock'),
                             ('namedPipeName', 'other'), ('httpsAddress', 'https://localhost/'),
                             ('clientCertificatePath', '/other.pem'), ('lateUnknown', ''), ('identityTokenPath', None)):
            changed = copy.deepcopy(original); changed['application'][field] = value
            self.refuse_before_nested('gateway', changed)

    def test_cross_role_percent_and_direct_source_token_references_refuse(self):
        original = self.role('gateway')
        for value in ('/run/credentials/mk8-drava-application.service/ipc', '%d/ipc',
                      '/etc/mk8.drava/ipc-token.txt', '/run/credentials/mk8-drava-gateway.service/../ipc'):
            changed = copy.deepcopy(original); changed['application']['identityTokenPath'] = value
            self.refuse_before_nested('gateway', changed, 'literal role credential')

    def test_controller_administrator_enrollment_management_and_discovery_withhold_profile(self):
        for role, field, value in (('application', 'controller', {}), ('application', 'controller', False),
                ('application', 'administratorTokenPath', '/secret'), ('application', 'managementPort', 18082),
                ('gateway', 'enrollmentRootFingerprint', 'A' * 64), ('gateway', 'managementPort', 18082),
                ('gateway', 'discoveryEnabled', True), ('gateway', 'discoveryEnabled', 0)):
            changed = self.role(role); previous = copy.deepcopy(changed); changed[field] = value
            self.refuse_before_nested(role, changed); self.set_role(role, previous)

    def test_http_https_ports_true_integer_defaults_and_pair_correspondence(self):
        original = self.role('gateway')
        for field, value in (('httpPort', 0), ('httpPort', 81), ('httpPort', True),
                             ('httpsPort', None), ('httpsPort', 443), ('registrationPort', 80),
                             ('registrationPort', 0), ('registrationPort', 65536)):
            changed = copy.deepcopy(original); changed[field] = value
            self.refuse_before_nested('gateway', changed)
        changed = copy.deepcopy(original); del changed['httpsPort']
        self.refuse_before_nested('gateway', changed, 'HTTPS0')

    def test_pair_canonical_loopback_and_declared_public_literals_are_not_assignment(self):
        for address in ('127.0.0.1', '::1', self.value['public']['ipv4']):
            for role, field in (('application', 'ingressAddress'), ('gateway', 'bindAddress')):
                changed = self.role(role); changed[field] = address; self.set_role(role, changed)
            self.assertEqual(self.admit()['source'], '/etc/mk8.drava/ipc-token.txt')
        self.assertFalse(self.candidate()['authority']['configuration_matches_network_and_storage_policy'])

    def test_unassigned_wildcard_scoped_and_mismatched_ingress_refuse_before_token(self):
        original = self.role('gateway')
        for address in ('0.0.0.0', '::', '192.168.90.20', '::1%lo', '::1%x\naccept', 'LOCALHOST', None):
            changed = copy.deepcopy(original); changed['bindAddress'] = address
            self.refuse_before_nested('gateway', changed, 'literal ingress')

    def test_complete_resource_integer_bounds_cover_zero_one_tib_and_invalid_widths(self):
        original = self.role('gateway')
        bounds = {'maxConcurrentExchanges': (1, 4096), 'maxHeaderBytes': (1024, 65536),
                  'maxRequestBodyBytes': (0, 1024 ** 4), 'frameBytes': (1024, 32768), 'streamWindowFrames': (1, 8)}
        for field, (low, high) in bounds.items():
            for value in (low, high):
                changed = copy.deepcopy(original); changed[field] = value; self.set_role('gateway', changed); self.admit()
            for value in (low - 1, high + 1, True, 1.0, None):
                changed = copy.deepcopy(original); changed[field] = value
                self.refuse_before_nested('gateway', changed, 'integer')
        self.set_role('gateway', original)

    def test_complete_plan_defaults_and_every_late_bound_are_validated(self):
        original = self.role('gateway')
        self.assertEqual(self.admit()['bytes'], 49)
        for field, (default, low, high) in self.n['DRAVA_PLAN_BOUNDS'].items():
            for value in (low, high):
                changed = copy.deepcopy(original); changed['plan'] = {field: value}; self.set_role('gateway', changed); self.admit()
            changed = copy.deepcopy(original); changed['plan'] = {field: high + 1}
            self.refuse_before_nested('gateway', changed, 'integer')
        changed = copy.deepcopy(original); changed['plan'] = {'refreshSeconds': 5, 'zzLater': 1}
        self.refuse_before_nested('gateway', changed, 'record')

    def test_plan_and_body_limits_null_wrong_types_and_oversized_rows_refuse(self):
        original = self.role('gateway')
        for field, value in (('plan', None), ('plan', []), ('requestBodyLimits', None),
                             ('requestBodyLimits', {}), ('requestBodyLimits', [{}] * 65)):
            changed = copy.deepcopy(original); changed[field] = value
            self.refuse_before_nested('gateway', changed)

    def test_entire_body_limit_rows_require_unique_exact_manifest_host_and_int64_bound(self):
        original = self.role('gateway'); host = self.value['domains']['mk8.drava']
        good = {'host': host, 'maxRequestBodyBytes': 1024 ** 4}
        changed = copy.deepcopy(original); changed['requestBodyLimits'] = [good]; self.set_role('gateway', changed); self.admit()
        for row in ({**good, 'host': host.upper()}, {**good, 'host': 'other.example.test'},
                    {**good, 'maxRequestBodyBytes': True}, {**good, 'maxRequestBodyBytes': 1024 ** 4 + 1},
                    {**good, 'lateUnknown': 0}):
            changed = copy.deepcopy(original); changed['requestBodyLimits'] = [good, row]
            self.refuse_before_nested('gateway', changed)

    def test_serving_trust_declarations_retain_case_and_mode_specific_fingerprints(self):
        original = self.role('gateway')
        for trust in ({}, {'mode': 'system'}, {'mode': 'pinned', 'rootFingerprint': 'A' * 64}):
            changed = copy.deepcopy(original); changed['servingTrust'] = trust; self.set_role('gateway', changed); self.admit()
        for trust in (None, {'mode': 'SYSTEM'}, {'mode': 'system', 'rootFingerprint': 'A' * 64},
                      {'mode': 'pinned', 'rootFingerprint': 'a' * 64}, {'mode': 'pinned', 'rootFingerprint': None},
                      {'mode': 'site-ca', 'lateUnknown': 1}):
            changed = copy.deepcopy(original); changed['servingTrust'] = trust
            self.refuse_before_nested('gateway', changed)

    def test_token_length_ascii_lf_and_opaque_commitments_match_original_trim_subset(self):
        token = self.root / 'etc/mk8.drava/ipc-token.txt'
        for raw in (b'A' * 32 + b'\n', b'Z_9-' * 63 + b'A\n', b'A' * 255 + b'\n'):
            token.write_bytes(raw); value = self.admit()
            self.assertEqual(value['bytes'], len(raw)); self.assertEqual(value['sha256'], hashlib.sha256(raw).hexdigest())
        for raw in (b'A' * 31 + b'\n', b'A' * 256 + b'\n', b'A' * 48, b' ' + b'A' * 48 + b'\n',
                    b'A' * 40 + b'\n\n', b'A' * 40 + b'\x00\n', b'A' * 40 + b'!\n'):
            token.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'token bytes'): self.admit()
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_missing_or_group_readable_nested_source_refuses_with_checked_cleanup(self):
        token = self.root / 'etc/mk8.drava/ipc-token.txt'; token.chmod(0o640)
        with self.assertRaisesRegex(ValueError, '0600'): self.admit()
        token.chmod(0o600); token.unlink()
        with self.assertRaises(FileNotFoundError): self.admit()
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_original_bootstrap_change_during_nested_observation_refuses_complete_output(self):
        reader = self.n['deployment_read']; path = self.root / 'etc/mk8.drava/gateway.json'
        def changed(name):
            raw = reader(name)
            if name == '/etc/mk8.drava/ipc-token.txt': path.write_bytes(path.read_bytes() + b'\n')
            return raw
        self.n['deployment_read'] = changed
        with self.assertRaisesRegex(ValueError, 'bootstrap changed'): self.admit()
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_bounded_stale_positive_digest_cannot_replace_missing_original_declarations(self):
        value = self.candidate(); self.value['stale_positive_application_receipt'] = {'source': value['source']}
        with self.assertRaisesRegex(ValueError, 'exact manifest'): self.candidate()
        del self.value['stale_positive_application_receipt']
        (self.root / 'etc/mk8.drava/application.json').unlink()
        with self.assertRaises(FileNotFoundError): self.candidate()

    def test_unenrolled_profile_withholds_all_runtime_and_tls_authority(self):
        self.assertEqual(self.role('gateway')['httpsPort'], 0)
        self.assertEqual(self.role('gateway').get('enrollmentRootFingerprint', ''), '')
        value = self.candidate()
        self.assertEqual(len(value['files']), 9); self.assertEqual(len(value['authority']), 27)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertFalse(value['authority']['systemd_parser_validated'])

    def test_whole_emitted_profile_preserves_originals_and_withholds_runtime_authority(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        row = next(row for row in value['configuration'] if row['file'] == '/etc/mk8.drava/application.json')
        self.assertEqual(row['ipc_identity']['bytes'], 49)
        self.assertEqual(before, self.snapshot())

    def test_whole_emitted_late_declaration_refusal_has_no_json_and_preserves_sources(self):
        control = self.role('gateway'); control['plan'] = {'refreshSeconds': 5, 'tlsHandshakeSeconds': True}
        self.set_role('gateway', control); self.manifest_file.write_bytes(encoded(self.value))
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(before, self.snapshot())

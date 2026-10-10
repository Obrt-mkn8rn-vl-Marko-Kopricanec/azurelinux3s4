"""Role-specific literal file declarations and the complete private emitted entry."""

import deployment_fixture as net_fixture

import collections
import copy
import hashlib
import json
import os
import unittest
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ReleaseFixture
import test_deployment_services as service_fixture


class EmailCredentialTests(ReleaseFixture):
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = service_fixture.DeploymentApplicationServiceTests.run_emitted

    def control(self, role='worker'):
        return json.loads((self.root / 'etc/mk8.email' / (role + '.json')).read_bytes())

    def observe(self, worker=None, gateway=None):
        return self.n['email_credential_observe']({'worker.json': encoded(self.control() if worker is None else worker),
            'gateway.json': encoded(self.control('gateway') if gateway is None else gateway)})

    def refuse(self, value, role='worker', message='.'):
        reader = Mock(); original = self.n['deployment_read']; self.n['deployment_read'] = reader
        try:
            args = {'worker': value} if role == 'worker' else {'gateway': value}
            with self.assertRaisesRegex((ValueError, TypeError), message): self.observe(**args)
            reader.assert_not_called()
        finally:
            self.n['deployment_read'] = original

    def secret(self, name='database-password.txt', role='worker'):
        return self.root / 'etc/mk8.email' / role / name

    def test_complete_original_config_and_nested_files_bind_without_secret_serialization(self):
        before = self.snapshot(); value = self.candidate(); rows = value['email_credentials']
        self.assertEqual([row['role'] for row in rows], ['worker', 'gateway'])
        self.assertEqual([len(row['inputs']) for row in rows], [8, 7])
        for row in rows:
            self.assertEqual(row['unit'], 'mk8-email-' + row['role'] + '.service')
            self.assertEqual(row['source_mode'], '0600'); self.assertTrue(row['checked_original_readback_and_close'])
            self.assertEqual(len(row['authority']), 11); self.assertTrue(all(flag is False for flag in row['authority'].values()))
            self.assertEqual([item['id'] for item in row['inputs']], sorted(item['id'] for item in row['inputs']))
            for item in row['inputs']:
                data = (self.root / item['source'][1:]).read_bytes()
                self.assertEqual(item['sha256'], hashlib.sha256(data).hexdigest()); self.assertEqual(item['bytes'], len(data))
                self.assertEqual(item['destination'], '/run/credentials/' + row['unit'] + '/' + item['id'])
                if item['id'] != 'config.json': self.assertNotIn(data.decode().rstrip(), json.dumps(value))
        self.assertEqual(before, self.snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_units_deliver_exact_sets_with_worker_only_material_absent_from_gateway(self):
        value = self.candidate(); units = {row['file']: row['content'] for row in value['files']}
        for row in value['email_credentials']:
            content = units['systemd/' + row['unit']]
            actual = [line for line in content.splitlines() if line.startswith('LoadCredential=')]
            self.assertEqual(actual, ['LoadCredential=' + item['id'] + ':' + item['source'] for item in row['inputs']])
            self.assertIn('Environment=MK8EMAIL_CONFIG_FILE=%d/config.json\n', content)
            self.assertNotIn('SetCredential=', content); self.assertNotIn('ExecStartPre=', content)
        gateway = units['systemd/mk8-email-gateway.service']
        for name in ('oauth-signing.txt', 'mfa-key.txt', 'dkim-key.pem'):
            self.assertNotIn(name, gateway)
        self.assertEqual(len(value['authority']), 27); self.assertTrue(all(flag is False for flag in value['authority'].values()))

    def test_delivery_is_independent_of_public_family_and_absent_admin_ipv6(self):
        for ipv4, ipv6 in ((net_fixture.nat4(), None), (None, net_fixture.PUBLIC6), (net_fixture.nat4(), net_fixture.PUBLIC6)):
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                self.value['public'].update(ipv4=ipv4, ipv6=ipv6); self.value['admin']['ipv6'] = None
                rows = self.candidate()['email_credentials']; self.assertEqual([len(row['inputs']) for row in rows], [8, 7])

    def test_missing_common_records_or_enabled_messaging_refuse_before_nested_reads(self):
        original = self.control()
        for field in ('Database', 'Messaging', 'ObjectStorage'):
            with self.subTest(field=field):
                value = copy.deepcopy(original); del value[field]; self.refuse(value)
        value = copy.deepcopy(original); value['Messaging']['Enabled'] = False; self.refuse(value)

    def test_unknown_case_alias_and_misspelled_selected_fields_refuse(self):
        original = self.control()
        for field in ('Database', 'Messaging', 'OAuth'):
            with self.subTest(field=field):
                value = copy.deepcopy(original); value[field.lower()] = value[field]; self.refuse(value)
        for field, key in (('Database', 'passwordFile'), ('Messaging', 'encryptionKeyFile'), ('ObjectStorage', 'Unknown')):
            with self.subTest(field=field, key=key):
                value = copy.deepcopy(original); value[field][key] = 'unselected'; self.refuse(value)

    def test_inline_secret_conflicts_and_wrong_types_refuse_every_selected_surface(self):
        original = self.control()
        for field, key in (('Database', 'Password'), ('Messaging', 'EncryptionKey'), ('ObjectStorage', 'ConnectionString'), ('OAuth', 'SigningKey'), ('Mfa', 'EncryptionKey')):
            for bad in ('opaque-inline', None, True, 1, []):
                with self.subTest(field=field, bad=bad):
                    value = copy.deepcopy(original); value[field][key] = bad; self.refuse(value)
        value = copy.deepcopy(original); value['Messaging']['DecryptionKeys'][0]['Key'] = 'inline'; self.refuse(value)

    def test_gateway_rejects_worker_only_values_and_even_unread_file_declarations(self):
        original = self.control('gateway')
        for field, key, bad in (('OAuth', 'SigningKey', 'inline'), ('OAuth', 'SigningKeyFile', '/worker-only'),
                                ('Mfa', 'EncryptionKey', 'inline'), ('Mfa', 'EncryptionKeyFile', '/worker-only'),
                                ('Dkim', 'PrivateKeyPath', '/worker-only')):
            with self.subTest(field=field, key=key):
                value = copy.deepcopy(original); value[field] = {key: bad}; self.refuse(value, 'gateway')

    def test_worker_disabled_optional_secrets_withhold_delivery_and_null_paths_are_allowed(self):
        value = self.control(); value['OAuth'] = {'SigningKeyFile': None}; value['Mfa'] = {'EncryptionKeyFile': None}
        value['Dkim'] = {'PrivateKeyPath': None}
        self.replace_configuration('mk8.email', 'worker.json', encoded(value))
        ids = {row['id'] for row in self.observe()[0]['inputs']}
        self.assertEqual(ids, {'config.json', 'database-password.txt', 'messaging-key.txt', 'messaging-decrypt-old.txt', 'blob-connection.txt'})

    def test_enabled_worker_features_require_their_exact_file_references(self):
        original = self.control()
        for field, key in (('OAuth', 'SigningKeyFile'), ('Mfa', 'EncryptionKeyFile'), ('Dkim', 'PrivateKeyPath')):
            with self.subTest(field=field):
                value = copy.deepcopy(original); del value[field][key]; self.refuse(value)

    def test_flags_are_actual_booleans_not_truthy_values(self):
        original = self.control()
        for field, key in (('Messaging', 'Enabled'), ('OAuth', 'EnableOAuth'), ('OAuth', 'EnableOpenIdConnect'), ('Mfa', 'EnableTotp'), ('Dkim', 'EnableSigning')):
            for bad in (0, 1, 'true', None, []):
                with self.subTest(field=field, key=key, bad=bad):
                    value = copy.deepcopy(original); value[field][key] = bad; self.refuse(value)

    def test_literal_paths_reject_specifiers_traversal_cross_role_and_decoded_controls(self):
        original = self.control()
        for bad in ('%d/database-password.txt', '${CREDENTIALS_DIRECTORY}/database-password.txt',
                    '/run/credentials/mk8-email-gateway.service/database-password.txt', '/etc/mk8.email/worker/database-password.txt',
                    '/run/credentials/mk8-email-worker.service/../database-password.txt', '/run/credentials/mk8-email-worker.service/database-password.txt\n', None, True):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['Database']['PasswordFile'] = bad; self.refuse(value)

    def test_tls_requires_complete_exact_pem_pair_and_withholds_usability(self):
        original = self.control('gateway')
        for field in ('CertificatePath', 'CertificateKeyPath'):
            with self.subTest(field=field):
                value = copy.deepcopy(original); del value['Tls'][field]; self.refuse(value, 'gateway')
        value = copy.deepcopy(original); value['Tls']['CertificatePath'] = '/tmp/pfx'; self.refuse(value, 'gateway')
        value['Tls'] = {'CertificatePath': None, 'CertificateKeyPath': None}
        self.replace_configuration('mk8.email', 'gateway.json', encoded(value))
        row = self.observe()[1]; self.assertFalse(row['authority']['tls_and_dkim_usable'])
        self.assertFalse(any(item['id'].startswith('tls-') for item in row['inputs']))

    def test_key_ids_reject_unsafe_noncanonical_and_duplicate_active_or_previous_values(self):
        original = self.control()
        for bad in ('primary', 'old/escape', 'OLD', '1old', 'a' * 65, '', None, True):
            with self.subTest(bad=bad):
                value = copy.deepcopy(original); value['Messaging']['DecryptionKeys'][0]['Id'] = bad; self.refuse(value)
        value = copy.deepcopy(original); value['Messaging']['DecryptionKeys'] *= 2; self.refuse(value)

    def test_late_malformed_key_or_other_role_prevents_all_nested_factory_work(self):
        original = self.control()
        for later in (None, {'Id': 'later', 'KeyFile': '/incorrect'}, {'Id': 'later', 'KeyFile': '/incorrect', 'Unknown': 1}):
            with self.subTest(later=later):
                value = copy.deepcopy(original); value['Messaging']['DecryptionKeys'].append(later); self.refuse(value)
        value = self.control('gateway'); value['Database']['PasswordFile'] = '/late-invalid'; self.refuse(value, 'gateway')

    def test_decryption_list_bound_precedes_any_protected_nested_read(self):
        value = self.control(); value['Messaging']['DecryptionKeys'] *= 33; self.refuse(value, message='bounded complete')
        for bad in (None, {}, True):
            value = self.control(); value['Messaging']['DecryptionKeys'] = bad; self.refuse(value)

    def test_size_and_role_aggregate_bounds_refuse_after_bounded_protected_observation(self):
        path = self.secret(); original = path.read_bytes(); path.write_bytes(b'x' * 16385)
        with self.assertRaisesRegex(ValueError, 'credential size'): self.observe()
        path.write_bytes(original); self.n['EMAIL_ROLE_TOTAL'] = 1
        with self.assertRaisesRegex(ValueError, 'credential size'): self.observe()

    def test_unprotected_mode_and_hardlink_refuse_without_input_mutation(self):
        path = self.secret(); path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, 'single-link 0600'): self.observe()
        path.chmod(0o600); os.link(path, self.root / 'alias')
        with self.assertRaisesRegex(ValueError, 'single-link 0600'): self.observe()

    def test_missing_symlink_and_fifo_secret_are_not_followed_or_blocked(self):
        path = self.secret(); path.unlink()
        with self.assertRaises(FileNotFoundError): self.observe()
        path.symlink_to(self.manifest_file)
        with self.assertRaisesRegex(ValueError, 'single-link 0600'): self.observe()
        path.unlink(); os.mkfifo(path, 0o600)
        with self.assertRaisesRegex(ValueError, 'single-link 0600'): self.observe()

    def test_checked_close_failure_cannot_produce_credentials(self):
        original = self.delivery.close; hit = [False]
        def closed(fd):
            original(fd)
            if not hit[0]: hit[0] = True; raise OSError('delivered Email checked-close failure')
        self.delivery.close = closed
        with self.assertRaisesRegex(OSError, 'checked-close'): self.observe()
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_original_configuration_is_reobserved_and_cannot_borrow_stale_capture(self):
        path = self.root / 'etc/mk8.email/worker.json'; data = path.read_bytes(); path.write_bytes(data + b' ')
        captured = {'worker.json': data, 'gateway.json': (self.root / 'etc/mk8.email/gateway.json').read_bytes()}
        with self.assertRaisesRegex(ValueError, 'original configuration'): self.n['email_credential_observe'](captured)

    def test_stale_positive_summary_cannot_supply_missing_raw_secret(self):
        old = self.candidate(); self.secret().unlink()
        with self.assertRaises(FileNotFoundError): self.candidate()
        self.assertEqual(old['email_credentials'][0]['role'], 'worker')

    def test_whole_emitted_positive_binds_literal_paths_and_preserves_all_inputs(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout); self.assertEqual([len(row['inputs']) for row in value['email_credentials']], [8, 7])
        self.assertTrue(all(flag is False for row in value['email_credentials'] for flag in row['authority'].values()))
        self.assertEqual(before, self.snapshot())

    def test_whole_emitted_late_reference_refusal_is_specific_and_publishes_no_json(self):
        value = self.control('gateway'); value['Messaging']['DecryptionKeys'].append({'Id': 'later', 'KeyFile': '%d/escape'})
        self.replace_configuration('mk8.email', 'gateway.json', encoded(value)); self.manifest_file.write_bytes(encoded(self.value))
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n'); self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()

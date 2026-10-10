"""Declared Email protocol/URL correspondence and explicit private delivery controls."""

import collections
import copy
import hashlib
import json
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ReleaseFixture
import test_deployment_services as service_fixture


class EmailPresentationTests(ReleaseFixture):
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = service_fixture.DeploymentApplicationServiceTests.run_emitted

    def role(self, role='gateway'):
        return json.loads((self.root / 'etc/mk8.email' / (role + '.json')).read_bytes())

    def replace(self, value, role='gateway'):
        self.replace_configuration('mk8.email', role + '.json', encoded(value))

    def observe(self):
        return self.n['email_presentation_observe']({role + '.json':
            (self.root / 'etc/mk8.email' / (role + '.json')).read_bytes() for role in ('worker', 'gateway')},
            self.n['deployment_manifest'](self.value))

    def refused(self, value, role='gateway', message='Email'):
        self.replace(value, role); original = self.n['email_credential_observe']; observer = Mock()
        self.n['email_credential_observe'] = observer
        try:
            before = self.snapshot()
            with self.assertRaisesRegex(ValueError, message): self.candidate()
            observer.assert_not_called(); self.assertEqual(before, self.snapshot())
        finally:
            self.n['email_credential_observe'] = original

    def test_complete_declared_profile_binds_originals_and_keeps_all_runtime_authorities_false(self):
        before = self.snapshot(); candidate = self.candidate(); observed = self.observe()
        self.assertEqual([row['role'] for row in observed['roles']], ['worker', 'gateway'])
        self.assertEqual(observed['roles'][0]['declared_mail_ports'], [])
        self.assertEqual(observed['roles'][1]['declared_mail_ports'], [25, 587, 993])
        self.assertEqual(observed['roles'][1]['declared_http_port'], 18081)
        self.assertEqual(len(observed['authority']), 9)
        self.assertTrue(all(flag is False for flag in observed['authority'].values()))
        for row in candidate['configuration']:
            self.assertEqual(row['sha256'], hashlib.sha256((self.root / row['file'][1:]).read_bytes()).hexdigest())
        self.assertEqual(before, self.snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_null_nonobject_unknown_and_wrong_case_protocol_records_refuse_before_nested_reads(self):
        original = self.role()
        for key in ('Smtp', 'Imap', 'Pop3', 'Sieve', 'Security'):
            for bad in (None, [], {'LateUnknown': True}):
                changed = copy.deepcopy(original); changed[key] = bad
                self.refused(changed, message='canonical Email')
        changed = copy.deepcopy(original); changed['smtp'] = changed.pop('Smtp')
        self.refused(changed, message='canonical Email')

    def test_hostname_requires_both_exact_declared_domains_and_refuses_loader_aliases(self):
        original = self.role()
        for role in ('worker', 'gateway'):
            for bad in ('localhost', 'other.example.test', 'Email.example.test', 'email.example.test.',
                        '', None, True, 'email.example.test\n'):
                changed = copy.deepcopy(original if role == 'gateway' else self.role(role))
                changed['Smtp']['Hostname'] = bad; self.refused(changed, role, 'hostname')

    def test_all_port_fields_are_true_ints_and_use_fixed_protocol_numbers_even_when_disabled(self):
        original = self.role()
        ports = {'Smtp': {'Port': 25, 'SubmissionPort': 587, 'ImplicitTlsPort': 465},
                 'Imap': {'Port': 143, 'ImplicitTlsPort': 993},
                 'Pop3': {'Port': 110, 'ImplicitTlsPort': 995}, 'Sieve': {'Port': 4190}}
        for record, fields in ports.items():
            for key, good in fields.items():
                for bad in (True, None, str(good), float(good), 0, 65536, good + 1):
                    changed = copy.deepcopy(original); changed.setdefault(record, {})[key] = bad
                    self.refused(changed)

    def test_all_selected_boolean_fields_refuse_int_null_string_and_container_values(self):
        original = self.role()
        fields = {'Smtp': ('EnableSmtp', 'EnableSubmission', 'EnableImplicitTls', 'EnableStartTls', 'RequireTls', 'RequireAuth', 'AllowRelay'),
                  'Imap': ('EnableImap', 'EnableImplicitTls'), 'Pop3': ('EnablePop3', 'EnableImplicitTls', 'EnableStartTls'),
                  'Sieve': ('EnableManageSieve', 'EnableStartTls'), 'Security': ('EnableSpfCheck', 'EnableDmarcCheck'),
                  'Jmap': ('IsDefault',), 'OAuth': ('EnableOAuth', 'EnableOpenIdConnect')}
        for record, keys in fields.items():
            for key in keys:
                for bad in (0, 1, None, 'true', []):
                    changed = copy.deepcopy(original); changed.setdefault(record, {})[key] = bad
                    self.refused(changed, message='boolean')

    def test_gateway_smtp_and_submission_require_declared_starttls_and_authentication(self):
        original = self.role()
        for field in ('EnableSmtp', 'EnableSubmission', 'EnableStartTls', 'RequireAuth'):
            changed = copy.deepcopy(original); changed['Smtp'][field] = False
            self.refused(changed, message='firewall profile')

    def test_authenticated_relay_and_requiretls_switches_are_declarations_without_usable_mail_claim(self):
        original = self.role()
        for relay in (False, True):
            for tls in (False, True):
                changed = copy.deepcopy(original); changed['Smtp'].update(AllowRelay=relay, RequireTls=tls)
                self.replace(changed); candidate = self.candidate(); observed = self.observe()
                self.assertFalse(candidate['authority']['mail_delivery_and_relay_refusal_proven'])
                self.assertFalse(observed['authority']['mail_delivery_auth_and_relay_refusal_proven'])

    def test_plain_imap_and_plain_pop3_are_absent_from_the_fixed_public_profile(self):
        original = self.role()
        for record, flag in (('Imap', 'EnableImap'), ('Pop3', 'EnablePop3')):
            changed = copy.deepcopy(original); changed.setdefault(record, {})[flag] = True
            self.refused(changed, message='firewall profile')

    def test_required_imaps_cannot_be_silently_disabled(self):
        value = self.role(); value['Imap']['EnableImplicitTls'] = False
        self.refused(value, message='firewall profile')

    def test_each_optional_protocol_switch_must_match_the_same_manifest(self):
        original = self.role()
        for record, field, manifest in (('Smtp', 'EnableImplicitTls', 'implicit_submission'),
                                      ('Pop3', 'EnableImplicitTls', 'pop3s'), ('Sieve', 'EnableManageSieve', 'sieve')):
            changed = copy.deepcopy(original); changed.setdefault(record, {})[field] = True
            self.refused(changed, message='firewall profile')
            self.value['mail'][manifest] = True; self.replace(changed)
            self.assertIn({'implicit_submission': 465, 'pop3s': 995, 'sieve': 4190}[manifest],
                          self.observe()['roles'][1]['declared_mail_ports'])
            self.candidate(); self.value['mail'][manifest] = False

    def test_every_optional_combination_has_exact_declared_ports_and_firewall_rows(self):
        original = self.role()
        for mask in range(8):
            enabled = {'implicit_submission': bool(mask & 1), 'pop3s': bool(mask & 2), 'sieve': bool(mask & 4)}
            self.value['mail'].update(enabled); changed = copy.deepcopy(original)
            changed['Smtp']['EnableImplicitTls'] = enabled['implicit_submission']
            changed['Pop3'] = {'EnableImplicitTls': enabled['pop3s']}
            changed['Sieve'] = {'EnableManageSieve': enabled['sieve']}; self.replace(changed)
            ports = [25, 587, 993] + [port for name, port in (('implicit_submission', 465), ('pop3s', 995), ('sieve', 4190)) if enabled[name]]
            self.assertEqual(self.observe()['roles'][1]['declared_mail_ports'], sorted(ports))
            self.candidate(); host = self.n['deployment_firewall'](self.n['deployment_manifest'](self.value))['content']
            self.assertIn('tcp dport { ' + ', '.join(map(str, sorted([53, 80, 443, *ports]))) + ' } accept', host)
            self.assertNotIn('143,', host); self.assertNotIn('110,', host)

    def test_enabled_sieve_requires_starttls_but_disabled_branch_keeps_typed_source_default(self):
        original = self.role(); original['Sieve'] = {'EnableStartTls': False}
        self.replace(original); self.candidate()
        self.value['mail']['sieve'] = True; original['Sieve']['EnableManageSieve'] = True
        self.refused(original, message='firewall profile')
        original['Sieve']['EnableStartTls'] = True; self.replace(original); self.candidate()

    def test_sieve_script_limit_is_bounded_for_both_roles_including_disabled_listener(self):
        for role in ('worker', 'gateway'):
            original = self.role(role)
            for bad in (0, 1001, True, None, 64.0, '64'):
                changed = copy.deepcopy(original); changed['Sieve'] = {'MaxScriptsPerUser': bad}
                self.refused(changed, role, 'integer')
            for good in (1, 1000):
                changed = copy.deepcopy(original); changed['Sieve'] = {'MaxScriptsPerUser': good}
                self.replace(changed, role); self.candidate()

    def test_gateway_http_declaration_matches_unit_while_worker_port_does_not_create_listener(self):
        original = self.role(); value = copy.deepcopy(original); value['Jmap']['Port'] = 18082
        self.refused(value, message='HTTP declaration')
        self.replace(original)
        value = self.role('worker'); value['Jmap'] = {'Port': 18082}; self.replace(value, 'worker')
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        self.assertIn('ASPNETCORE_URLS=http://127.0.0.1:18081\n', units['systemd/mk8-email-gateway.service'])
        self.assertEqual(self.observe()['roles'][0]['declared_mail_ports'], [])

    def test_gateway_omitted_http_port_uses_original8081_default_and_refuses_fixed18081_profile(self):
        value = self.role(); del value['Jmap']['Port']
        self.refused(value, message='HTTP declaration')

    def test_all_http_port_numeric_width_and_type_errors_refuse_before_nested_reads(self):
        original = self.role()
        for bad in (0, 65536, True, None, 18081.0, '18081'):
            changed = copy.deepcopy(original); changed['Jmap']['Port'] = bad
            self.refused(changed, message='integer')

    def test_canonical_https_origin_optional_slash_and_null_fallback_keep_original_bytes(self):
        original = self.role()
        for role in ('worker', 'gateway'):
            for origin in (None, 'https://email.example.test', 'https://email.example.test/'):
                changed = copy.deepcopy(original if role == 'gateway' else self.role(role))
                for record in ('Jmap', 'OAuth'): changed.setdefault(record, {})['PublicBaseUrl'] = origin
                self.replace(changed, role); before = self.snapshot(); observed = self.observe()
                row = next(row for row in observed['roles'] if row['role'] == role)
                self.assertEqual(row['jmap_origin'], origin or 'https://email.example.test')
                self.assertEqual(row['oauth_origin'], origin or 'https://email.example.test')
                self.candidate(); self.assertEqual(before, self.snapshot())

    def test_public_urls_refuse_nonhttps_other_host_path_userinfo_query_fragment_and_decoded_text(self):
        original = self.role()
        for record in ('Jmap', 'OAuth'):
            for bad in ('http://email.example.test', 'https://other.example.test', 'https://email.example.test:443',
                        'https://user@email.example.test', 'https://email.example.test/path',
                        'https://email.example.test?x=1', 'https://email.example.test#x',
                        'HTTPS://email.example.test', 'https://email.example.test/%0a', '', True,
                        'https://email.example.test\n'):
                changed = copy.deepcopy(original); changed.setdefault(record, {})['PublicBaseUrl'] = bad
                self.refused(changed, message='HTTPS origin')

    def test_late_worker_url_refusal_prevents_gateway_nested_credential_observation(self):
        value = self.role('worker'); value['OAuth']['PublicBaseUrl'] = 'https://elsewhere.example.test'
        self.refused(value, 'worker', 'HTTPS origin')

    def test_jmap_default_and_oidc_require_their_source_enablement_dependencies(self):
        original_worker = self.role('worker')
        value = self.role(); value['Jmap']['EnableJmap'] = False
        self.refused(value, message='JMAP and OAuth')
        value = self.role('worker'); value['OAuth']['EnableOAuth'] = False
        self.refused(value, 'worker', 'JMAP and OAuth')
        self.replace(original_worker, 'worker')
        value = self.role(); value['Jmap'].update(EnableJmap=False, IsDefault=False)
        self.replace(value); self.candidate()

    def test_production_hash_scheme_and_unapproved_builtin_spf_dmarc_declarations_refuse(self):
        for role in ('worker', 'gateway'):
            original = self.role(role)
            for field, bad in (('PasswordHashScheme', 'bcrypt'), ('PasswordHashScheme', None),
                               ('EnableSpfCheck', True), ('EnableDmarcCheck', True)):
                changed = copy.deepcopy(original); changed['Security'] = {field: bad}
                self.refused(changed, role, 'production security')

    def test_tls_gateway_requires_both_exact_literal_role_file_references(self):
        original = self.role()
        for field in ('CertificatePath', 'CertificateKeyPath'):
            for bad in (None, '', '/etc/private.pem', '/run/credentials/mk8-email-worker.service/tls-key.pem',
                        '%d/tls-key.pem', True):
                changed = copy.deepcopy(original); changed['Tls'][field] = bad
                self.refused(changed, message='gateway Email TLS')

    def test_ipv4_ipv6_and_dual_public_variants_do_not_claim_actual_ipv6_mail_or_proxy_enforcement(self):
        for ipv4, ipv6 in (('192.168.1.20', None), (None, '2001:4860::20'), ('192.168.1.20', '2001:4860::20')):
            self.value['public'].update(ipv4=ipv4, ipv6=ipv6); candidate = self.candidate(); observed = self.observe()
            self.assertFalse(observed['authority']['actual_ipv6_mail_listeners_usable'])
            self.assertFalse(observed['authority']['public_https_proxy_routes_admitted'])
            self.assertFalse(candidate['authority']['configuration_matches_network_and_storage_policy'])

    def test_whole_emitted_positive_preserves_original_inputs_and_all_false_service_authorities(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        candidate = json.loads(result.stdout); self.assertTrue(all(flag is False for flag in candidate['authority'].values()))
        self.assertEqual(len(candidate['files']), 9); self.assertEqual(before, self.snapshot())

    def test_whole_emitted_late_gateway_protocol_conflict_refuses_no_json_without_mutation(self):
        value = self.role(); value['Sieve'] = {'EnableManageSieve': True}; self.replace(value)
        self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n'); self.assertEqual(before, self.snapshot())

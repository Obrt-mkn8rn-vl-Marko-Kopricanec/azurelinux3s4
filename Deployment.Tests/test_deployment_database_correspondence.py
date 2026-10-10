"""Database source/profile correspondence before inactive private publication."""

import collections
import copy
import hashlib
import json
from unittest.mock import Mock

from test_deployment_policy import encoded
from test_deployment_releases import ROOT, ReleaseFixture
from test_deployment_publication import PublicationOS
import test_deployment_application_publication as publication_fixture
import test_deployment_services as service_fixture


class DatabaseCorrespondenceTests(ReleaseFixture):
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    publish = publication_fixture.ApplicationPublicationTests.publish
    store_snapshot = publication_fixture.ApplicationPublicationTests.store_snapshot
    source_snapshot = publication_fixture.ApplicationPublicationTests.source_snapshot
    run_emitted = publication_fixture.ApplicationPublicationTests.run_emitted

    def setUp(self):
        super().setUp()
        for name in ('Deployment/publication.py', 'Deployment/application_publication.py'):
            exec(compile((ROOT / name).read_bytes(), name, 'exec'), self.n)
        self.delivery = PublicationOS(self.root); self.n['dep_os'] = self.delivery
        self.store = self.root / 'var/lib/azurelinux3s4/application-candidates'
        self.store.mkdir(parents=True, mode=0o700)
        for parent in self.store.parents:
            if parent == self.root.parent: break
            parent.chmod(0o700)
        self.capture = None

    def observe(self, candidate=None):
        return self.n['application_database_observe'](candidate or self.candidate())

    def dns(self):
        return self.root / 'etc/mk8.dns/controller/database.txt'

    def change_dns(self, old, new):
        self.dns().write_bytes(self.dns().read_bytes().replace(old, new))

    def role(self, role):
        return json.loads((self.root / 'etc/mk8.email' / (role + '.json')).read_bytes())

    def replace(self, role, value):
        self.replace_configuration('mk8.email', role + '.json', encoded(value))

    def refused(self, message='database'):
        before = self.source_snapshot(); lock = Mock(side_effect=AssertionError('store open forbidden'))
        original = self.n['publication_store']; self.n['publication_store'] = lock
        try:
            with self.assertRaisesRegex((ValueError, OSError), message): self.publish()
            lock.assert_not_called(); self.assertEqual(self.store_snapshot(), {})
            self.assertEqual(self.source_snapshot(), before)
            self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))
        finally:
            self.n['publication_store'] = original

    def test_complete_original_sources_and_fixed_role_endpoints_are_hash_bound(self):
        before = self.source_snapshot(); value = self.observe()
        self.assertEqual([row['role'] for row in value['roles']], ['dns-controller', 'email-worker', 'email-gateway'])
        self.assertEqual([row['login_role'] for row in value['roles']], ['mk8dns', 'mk8email_worker', 'mk8email_gateway'])
        self.assertEqual(len(value['sources']), 6)
        for row in value['sources']:
            raw = (self.root / row['file'][1:]).read_bytes()
            self.assertEqual(row['bytes'], len(raw)); self.assertEqual(row['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(before, self.source_snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_both_profile_files_minimum_version_and_all_authorities_stay_false(self):
        value = self.observe(); files, profile = self.n['postgresql_profile']()
        self.assertEqual(value['profile_files'], [{key: row[key] for key in ('file', 'bytes', 'sha256')} for row in files])
        self.assertEqual(value['minimum_server_version_num'], 170000)
        self.assertEqual(len(value['authority']), 10)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertFalse(profile['authority']['application_connection_strings_reconciled'])

    def test_password_bytes_and_dns_connection_string_are_never_serialized(self):
        value = self.observe(); output = json.dumps(value)
        self.assertNotIn('finite-model-only-password', output)
        self.assertNotIn('finite opaque Email input', output)
        self.assertNotIn('Password=', output)
        self.assertNotIn('database_connections_usable": true', output)

    def test_unquoted_dns_parameter_order_can_change_without_changing_endpoints(self):
        original = self.observe()['roles'][0]
        self.dns().write_bytes(b';'.join(reversed(self.dns().read_bytes().split(b';'))))
        self.assertEqual(self.observe()['roles'][0], original)

    def test_dns_remote_loopback_relative_and_multiple_hosts_refuse(self):
        original = self.dns().read_bytes()
        for host in (b'localhost', b'127.0.0.1', b'::1', b'run/postgresql', b'/tmp', b'/run/postgresql,/other'):
            self.dns().write_bytes(original.replace(b'/run/postgresql', host)); self.refused('DNS database declaration')

    def test_dns_port_database_and_login_must_each_match_profile(self):
        original = self.dns().read_bytes()
        for old, new in ((b'Port=5432', b'Port=5433'), (b'Database=mk8dns', b'Database=other'),
                         (b'Username=mk8dns', b'Username=postgres')):
            self.dns().write_bytes(original.replace(old, new)); self.refused('DNS database declaration')

    def test_dns_duplicate_and_alias_keys_refuse_before_storage(self):
        original = self.dns().read_bytes()
        for raw in (original + b';Host=/run/postgresql', original.replace(b'Username=', b'User ID='),
                    original.replace(b'Host=', b'Server='), original.replace(b'Host=', b'host=')):
            self.dns().write_bytes(raw); self.refused('DNS database')

    def test_dns_missing_parameters_and_empty_values_refuse(self):
        original = self.dns().read_bytes()
        for part in original.split(b';'):
            for raw in (b';'.join(x for x in original.split(b';') if x != part),
                        original.replace(part, part.split(b'=')[0] + b'=')):
                self.dns().write_bytes(raw); self.refused('DNS database')

    def test_dns_optional_overrides_and_terminal_separator_are_outside_subset(self):
        original = self.dns().read_bytes()
        for suffix in (b';', b';Options=-crole=postgres', b';Passfile=/tmp/file', b';SSL Mode=Disable'):
            self.dns().write_bytes(original + suffix); self.refused('DNS database')

    def test_dns_quoted_escaped_control_unicode_and_terminal_lf_refuse(self):
        original = self.dns().read_bytes()
        for raw in (original + b'\n', original + b'\r\n', original + b'\x00', original + 'é'.encode(),
                    original.replace(b'/run/postgresql', b'"/run/postgresql"'),
                    original.replace(b'finite-model-only-password', b"'quoted-password'")):
            self.dns().write_bytes(raw); self.refused('DNS database')

    def test_dns_password_subset_both_size_boundaries_and_unsupported_characters(self):
        original = self.dns().read_bytes(); marker = b'finite-model-only-password'
        for size in (16, 128):
            self.dns().write_bytes(original.replace(marker, b'A' * size)); self.observe()
        for password in (b'A' * 15, b'A' * 129, b'ABC=passwordABCDEF', b'ABC"passwordABCDE', b'ABC passwordABCDE'):
            self.dns().write_bytes(original.replace(marker, password)); self.refused('DNS database')

    def test_empty_and_overlong_dns_inputs_refuse(self):
        for raw in (b'', b'A' * 4097):
            self.dns().write_bytes(raw); self.refused('.')

    def test_email_each_role_requires_its_distinct_profile_login(self):
        for role in ('worker', 'gateway'):
            original = self.role(role)
            for user in ('postgres', 'mk8email', 'mk8email_' + ('gateway' if role == 'worker' else 'worker')):
                value = copy.deepcopy(original); value['Database']['Username'] = user
                self.replace(role, value); self.refused('Email database declaration')
            self.replace(role, original)

    def test_email_default_postgres_login_refuses_inactive_storage(self):
        value = self.role('worker'); del value['Database']['Username']
        self.replace('worker', value); self.refused('Email database declaration')

    def test_email_arbitrary_database_name_is_a_declaration_but_cannot_be_published(self):
        for role in ('worker', 'gateway'):
            value = self.role(role); value['Database']['Name'] = 'mail_90'; self.replace(role, value)
        self.candidate()  # Accepted generic declaration producer is unchanged.
        self.refused('Email database declaration')

    def test_email_localhost_requires_literal_loopback_resolution_before_publication(self):
        for role in ('worker', 'gateway'):
            value = self.role(role); value['Database']['Host'] = 'localhost'; self.replace(role, value)
        self.candidate(); self.refused('Email database declaration')

    def test_email_both_literal_loopback_families_are_supported(self):
        for host in ('127.0.0.1', '::1'):
            for role in ('worker', 'gateway'):
                value = self.role(role); value['Database']['Host'] = host; self.replace(role, value)
            self.assertEqual([row['host'] for row in self.observe()['roles'][1:]], [host, host])

    def test_email_nondefault_port_declaration_cannot_be_published(self):
        for role in ('worker', 'gateway'):
            value = self.role(role); value['Database']['Port'] = 5433; self.replace(role, value)
        self.candidate(); self.refused('Email database declaration')

    def test_late_gateway_mismatch_refuses_before_any_new_nested_reads(self):
        value = self.role('gateway'); value['Database']['Username'] = 'postgres'; self.replace('gateway', value)
        candidate = self.candidate(); original = self.n['deployment_read']; calls = []
        def read(path):
            calls.append(path); return original(path)
        self.n['deployment_read'] = read
        with self.assertRaisesRegex(ValueError, 'Email database declaration'): self.observe(candidate)
        self.assertEqual(calls, ['/etc/mk8.email/worker.json', '/etc/mk8.email/gateway.json'])

    def test_stale_candidate_cannot_replace_changed_original_startup(self):
        candidate = self.candidate(); path = self.root / 'etc/mk8.email/gateway.json'
        path.write_bytes(path.read_bytes().replace(b'mk8email_gateway', b'mk8email_worker'))
        with self.assertRaisesRegex(ValueError, 'source byte correspondence'): self.observe(candidate)

    def test_stale_dns_password_commitment_cannot_replace_actual_bytes(self):
        candidate = self.candidate(); self.change_dns(b'finite-model-only-password', b'changed-model-only-password')
        with self.assertRaisesRegex(ValueError, 'source byte correspondence'): self.observe(candidate)

    def test_stale_email_password_commitment_cannot_replace_actual_bytes(self):
        candidate = self.candidate(); path = self.root / 'etc/mk8.email/gateway/database-password.txt'
        path.write_bytes(b'changed opaque input\n')
        with self.assertRaisesRegex(ValueError, 'source byte correspondence'): self.observe(candidate)

    def test_missing_or_duplicate_original_commitments_refuse(self):
        original = self.candidate()
        for duplicate in (False, True):
            candidate = copy.deepcopy(original); rows = candidate['configuration']
            index = next(i for i, row in enumerate(rows) if row['file'] == '/etc/mk8.email/gateway.json')
            rows.append(dict(rows[index])) if duplicate else rows.pop(index)
            with self.assertRaisesRegex(ValueError, 'one complete original'): self.observe(candidate)

    def test_last_original_reread_change_refuses_complete_receipt(self):
        candidate = self.candidate(); original = self.n['deployment_read']; counts = collections.Counter()
        def read(path):
            counts[path] += 1; raw = original(path)
            return raw + b'x' if path.endswith('/gateway/database-password.txt') and counts[path] == 2 else raw
        self.n['deployment_read'] = read
        with self.assertRaisesRegex(ValueError, 'changed after admission'): self.observe(candidate)

    def test_full_inactive_intent_binds_receipt_and_contains_no_passwords(self):
        digest, contents = self.n['application_publication_plan'](encoded(self.value), self.n['bundle'])
        intent = json.loads(contents['publication.json']); receipt = intent['database_profile_correspondence']
        self.assertEqual(receipt, self.observe())
        self.assertEqual(digest, hashlib.sha256(contents['publication.json']).hexdigest())
        self.assertFalse(intent['activation_authorized']); self.assertEqual(len(contents), 14)
        self.assertNotIn('finite-model-only-password', contents['publication.json'].decode())
        self.assertNotIn('database_profile_correspondence', json.loads(contents['candidate.json']))

    def test_changed_dns_password_hash_names_new_inactive_bundle(self):
        before = self.publish(); self.change_dns(b'finite-model-only-password', b'changed-model-only-password')
        after = self.publish(); self.assertNotEqual(before['publication_sha256'], after['publication_sha256'])
        self.assertTrue((self.root / before['bundle'][1:]).is_dir())

    def test_whole_emitted_positive_retains_source_commitments_and_false_authorities(self):
        before = self.source_snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        receipt = json.loads(result.stdout); final = self.root / receipt['bundle'][1:]
        intent = json.loads((final / 'publication.json').read_bytes())
        self.assertEqual(intent['database_profile_correspondence'], self.observe())
        self.assertTrue(all(flag is False for flag in receipt['authority'].values()))
        self.assertTrue(all(flag is False for flag in intent['database_profile_correspondence']['authority'].values()))
        self.assertEqual(before, self.source_snapshot())

    def test_whole_emitted_late_gateway_login_refuses_no_json_or_store_mutation(self):
        value = self.role('gateway'); value['Database']['Username'] = 'postgres'; self.replace('gateway', value)
        self.manifest_file.write_bytes(encoded(self.value)); before = self.source_snapshot()
        result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Inactive application candidate publication refused\n')
        self.assertEqual(self.store_snapshot(), {}); self.assertEqual(before, self.source_snapshot())

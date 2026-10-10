"""Original Sava account/key declarations, bounded limits and private storage refusal."""

import base64
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


class SavaPolicyTests(ReleaseFixture):
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

    def raw(self, leaf):
        return (self.root / 'etc/mk8.sava' / leaf).read_bytes()

    def replace(self, leaf, raw):
        self.replace_configuration('mk8.sava', leaf, raw)

    def observe(self, candidate=None):
        return self.n['application_sava_observe'](candidate or self.candidate())

    def refused(self, message='Sava'):
        before = self.source_snapshot(); original = self.n['publication_store']
        store = Mock(side_effect=AssertionError('store IO forbidden')); self.n['publication_store'] = store
        try:
            with self.assertRaisesRegex(ValueError, message): self.publish()
            store.assert_not_called(); self.assertEqual(self.store_snapshot(), {})
            self.assertEqual(before, self.source_snapshot())
            self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))
        finally: self.n['publication_store'] = original

    def test_all_four_original_sources_and_key_fingerprints_are_bound(self):
        before = self.source_snapshot(); value = self.observe()
        self.assertEqual(value['default_account'], 'fixture'); self.assertEqual(len(value['accounts']), 1)
        self.assertEqual(len(value['sources']), 4)
        for row in value['sources']:
            raw = (self.root / row['file'][1:]).read_bytes()
            self.assertEqual(row['bytes'], len(raw)); self.assertEqual(row['sha256'], hashlib.sha256(raw).hexdigest())
        row = value['accounts'][0]
        self.assertEqual(row['name'], 'fixture')
        self.assertEqual(row['authentication_key']['decoded_bytes'], 32)
        self.assertEqual(row['data_key']['decoded_bytes'], 32)
        self.assertEqual(before, self.source_snapshot())

    def test_all_new_authorities_false_and_no_key_contents_serialized(self):
        value = self.observe(); self.assertEqual(len(value['authority']), 10)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        output = json.dumps(value)
        for key in (base64.b64encode(b'A' * 32).decode(), base64.b64encode(b'B' * 32).decode()):
            self.assertNotIn(key, output)
        self.assertFalse(value['authority']['key_entropy_and_crypto_usable'])

    def test_multiple_accounts_are_complete_sorted_and_default_selects_declared_name(self):
        self.replace('policy.env', self.raw('policy.env') + b'Sava__Accounts__aaa=' + base64.b64encode(b'C' * 32) + b'\n')
        self.replace('application.env', self.raw('application.env') + b'Sava__DataEncryptionKeys__aaa=' + base64.b64encode(b'D' * 32) + b'\n')
        value = self.observe(); self.assertEqual([row['name'] for row in value['accounts']], ['aaa', 'fixture'])

    def test_missing_or_unknown_default_account_refuses(self):
        original = self.raw('policy.env')
        for raw in (original.replace(b'Sava__DefaultAccount=fixture\n', b''),
                    original.replace(b'DefaultAccount=fixture', b'DefaultAccount=missing')):
            self.replace('policy.env', raw); self.refused('default must select')

    def test_invalid_account_names_are_not_dictionary_aliases(self):
        common, application = self.raw('policy.env'), self.raw('application.env')
        for name in (b'ab', b'a' * 25, b'Upper', b'with-dash', b'with_underscore', b'fixture__child'):
            self.replace('policy.env', common.replace(b'fixture', name))
            self.replace('application.env', application.replace(b'fixture', name))
            self.refused('EnvironmentFile' if b'-' in name else 'account policy')

    def test_empty_and_overfull_account_sets_refuse(self):
        original = self.raw('policy.env')
        self.replace('policy.env', b'\n'.join(line for line in original.splitlines() if not line.startswith(b'Sava__Accounts__')) + b'\n')
        self.refused('bounded account set')
        key = base64.b64encode(b'A' * 32)
        extra = b''.join(b'Sava__Accounts__account' + str(i).encode() + b'=' + key + b'\n' for i in range(32))
        self.replace('policy.env', original + extra); self.refused('bounded account set')

    def test_authentication_and_data_keys_must_be_canonical_base64(self):
        for leaf, marker in (('policy.env', base64.b64encode(b'A' * 32)), ('application.env', base64.b64encode(b'B' * 32))):
            original = self.raw(leaf)
            for key in (b'not-a-runtime-proof', b'AAAA=', b'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF=', b'A==='):
                self.replace(leaf, original.replace(marker, key)); self.refused('.')
            self.replace(leaf, original)

    def test_key_decoded_size_boundaries_are_observed_without_entropy_claim(self):
        for size in (32, 512):
            key = base64.b64encode(b'A' * size).decode(); self.assertEqual(self.n['sava_key'](key)['decoded_bytes'], size)
        for size in (31, 513):
            with self.assertRaisesRegex(ValueError, 'key bytes'): self.n['sava_key'](base64.b64encode(b'A' * size).decode())

    def test_missing_explicit_data_key_refuses_even_though_original_allows_fallback(self):
        self.replace('application.env', b'Sava__DataPath=/var/lib/mk8.sava/application\n')
        self.candidate(); self.refused('complete explicit Sava data-key')

    def test_late_data_key_for_unknown_account_refuses_complete_plan(self):
        self.replace('application.env', self.raw('application.env') + b'Sava__DataEncryptionKeys__unknown=' + base64.b64encode(b'C' * 32) + b'\n')
        self.refused('declared account')

    def test_duplicate_env_rows_refuse_before_policy_can_collapse_them(self):
        self.replace('policy.env', self.raw('policy.env') + b'Sava__Accounts__fixture=' + base64.b64encode(b'C' * 32) + b'\n')
        self.refused('EnvironmentFile')

    def test_true_or_noncanonical_anonymous_and_cross_account_flags_refuse(self):
        original = self.raw('policy.env')
        for field in (b'AllowAnonymousPublicAccess', b'EnableCrossAccountDeduplication'):
            for value in (b'true', b'False', b'0', b'falsee'):
                self.replace('policy.env', original + b'Sava__' + field + b'=' + value + b'\n'); self.refused('false public/dedup')

    def test_explicit_false_flags_preserve_defaults_and_false_enforcement_claims(self):
        self.replace('policy.env', self.raw('policy.env') + b'Sava__AllowAnonymousPublicAccess=false\nSava__EnableCrossAccountDeduplication=false\n')
        self.assertFalse(self.observe()['authority']['public_anonymous_access_refusal_proven'])

    def test_unknown_common_application_and_gateway_settings_refuse_storage(self):
        for leaf, extra in (('policy.env', b'Sava__Unknown=1\n'),
                            ('application.env', b'ApplicationHosting__CertificateFile=/tmp/cert\n'),
                            ('gateway.env', b'Gateway__Unknown=1\n')):
            original = self.raw(leaf); self.replace(leaf, original + extra)
            self.candidate(); self.refused('Sava'); self.replace(leaf, original)

    def test_source_defaults_for_application_and_gateway_admission_limits(self):
        limits = self.observe()['limits']
        self.assertEqual(limits['application'], {'MaximumReadSessions': 256, 'MaximumConcurrentRpcRequests': 16, 'MaximumQueuedRpcRequests': 128})
        self.assertEqual(limits['gateway'], {'MaximumConcurrentRequests': 32, 'MaximumQueuedRequests': 128, 'MaximumStagingBytes': 10737418240})

    def test_each_limit_accepts_exact_edges_and_refuses_beyond(self):
        for leaf, prefix, bounds in (('application.env', 'ApplicationHosting__', self.n['SAVA_APPLICATION_BOUNDS']),
                                     ('gateway.env', 'Gateway__', self.n['SAVA_GATEWAY_BOUNDS'])):
            original = self.raw(leaf)
            for field, (_, minimum, maximum) in bounds.items():
                for number in (minimum, maximum):
                    self.replace(leaf, original + (prefix + field + '=' + str(number) + '\n').encode()); self.observe()
                for number in (minimum - 1, maximum + 1):
                    self.replace(leaf, original + (prefix + field + '=' + str(number) + '\n').encode()); self.refused('.')
            self.replace(leaf, original)

    def test_limit_aliases_booleans_signs_and_width_refuse(self):
        original = self.raw('gateway.env')
        for number in (b'true', b'01', b'+1', b'1.0', b'10000000000000'):
            self.replace('gateway.env', original + b'Gateway__MaximumConcurrentRequests=' + number + b'\n'); self.refused('limit')

    def test_late_gateway_limit_refuses_without_store_access(self):
        self.replace('gateway.env', self.raw('gateway.env') + b'Gateway__MaximumStagingBytes=10737418241\n')
        self.refused('limit')

    def test_changed_original_env_cannot_borrow_old_candidate(self):
        candidate = self.candidate(); self.replace('gateway.env', self.raw('gateway.env') + b'Gateway__MaximumQueuedRequests=0\n')
        with self.assertRaisesRegex(ValueError, 'source byte correspondence'): self.observe(candidate)

    def test_final_rpc_source_reread_change_refuses_receipt(self):
        candidate = self.candidate(); original = self.n['deployment_read']; counts = collections.Counter()
        def read(path):
            raw = original(path); counts[path] += 1
            return raw + b'x' if path == '/etc/mk8.sava/rpc.key' and counts[path] == 2 else raw
        self.n['deployment_read'] = read
        with self.assertRaisesRegex(ValueError, 'changed after admission'): self.observe(candidate)

    def test_missing_or_duplicate_original_source_commitment_refuses(self):
        original = self.candidate()
        for duplicate in (False, True):
            value = copy.deepcopy(original); rows = value['configuration']
            index = next(i for i, row in enumerate(rows) if row['file'] == '/etc/mk8.sava/gateway.env')
            rows.append(dict(rows[index])) if duplicate else rows.pop(index)
            with self.assertRaisesRegex(ValueError, 'one complete original'): self.observe(value)

    def test_intent_binds_policy_while_general_candidate_schema_remains_unchanged(self):
        digest, contents = self.n['application_publication_plan'](encoded(self.value), self.n['bundle'])
        intent = json.loads(contents['publication.json']); self.assertEqual(intent['sava_policy_correspondence'], self.observe())
        self.assertNotIn('sava_policy_correspondence', json.loads(contents['candidate.json']))
        self.assertEqual(digest, hashlib.sha256(contents['publication.json']).hexdigest()); self.assertEqual(len(contents), 13)

    def test_whole_emitted_positive_binds_original_policy_and_false_authorities(self):
        before = self.source_snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout); folder = self.root / value['bundle'][1:]
        receipt = json.loads((folder / 'publication.json').read_bytes())['sava_policy_correspondence']
        self.assertEqual(receipt, self.observe()); self.assertTrue(all(flag is False for flag in receipt['authority'].values()))
        self.assertEqual(before, self.source_snapshot())

    def test_whole_emitted_late_key_refuses_no_json_and_no_store_mutation(self):
        self.replace('application.env', self.raw('application.env') + b'Sava__DataEncryptionKeys__unknown=' + base64.b64encode(b'C' * 32) + b'\n')
        self.manifest_file.write_bytes(encoded(self.value)); before = self.source_snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Inactive application candidate publication refused\n')
        self.assertEqual(self.store_snapshot(), {}); self.assertEqual(before, self.source_snapshot())

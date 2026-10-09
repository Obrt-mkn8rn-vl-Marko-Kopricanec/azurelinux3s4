import copy
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_baselines as baselines
import test_update_effects as effects
import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_provider_matches as providers
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class TriggerCountPlanTests(unittest.TestCase):
    setUpClass = classmethod(baselines.InstalledVersionInventoryTests.setUpClass.__func__)
    observations = staticmethod(baselines.InstalledVersionInventoryTests.observations)
    baseline = baselines.InstalledVersionInventoryTests.baseline

    def plan(self, incoming=None):
        values = self.observations()
        return self.namespace['trigger_count_plan'](values, self.baseline(values), incoming or [])

    def test_complete_scriptless_kernel_and_pseudo_key_counts_include_all_instances(self):
        inventory, rows = self.plan()
        self.assertEqual([(row['name'], row['inventory_count'], row['installed_instances']) for row in rows],
                         [('gpg-pubkey', 1, [3]), ('kernel', 2, [9, 12])])
        self.assertEqual(inventory['headers'], 3)

    def test_incoming_names_do_not_add_credit_to_current_installed_counts(self):
        _, rows = self.plan([{'name': 'new', 'file': 'packages/0.rpm'}, {'name': 'kernel', 'file': 'packages/1.rpm'}])
        self.assertEqual([(row['name'], row['inventory_count']) for row in rows], [('gpg-pubkey', 1), ('kernel', 2), ('new', 0)])
        self.assertEqual(rows[-1]['installed_instances'], []); self.assertEqual(rows[-1]['incoming_files'], ['packages/0.rpm'])

    def test_duplicate_incoming_names_retain_every_distinct_file_without_install_count_inference(self):
        _, rows = self.plan([{'name': 'new', 'file': 'packages/2.rpm'}, {'name': 'new', 'file': 'packages/0.rpm'}])
        self.assertEqual(rows[-1]['incoming_files'], ['packages/0.rpm', 'packages/2.rpm'])
        self.assertEqual(rows[-1]['inventory_count'], 0)

    def test_invalid_name_file_and_duplicate_file_refuse_the_complete_plan(self):
        for incoming in ([{'name': 'x\n', 'file': 'packages/0.rpm'}], [{'name': 'x', 'file': 'packages/00.rpm'}],
                         [{'name': 'x', 'file': 'packages/128.rpm'}], [{'name': 'x', 'file': '../x'}],
                         [{'name': 'a', 'file': 'packages/0.rpm'}, {'name': 'b', 'file': 'packages/0.rpm'}]):
            with self.subTest(incoming=incoming), self.assertRaises(ValueError): self.plan(incoming)

    def test_name_and_serialization_bounds_refuse_before_native_binding(self):
        for name in ('TRIGGER_COUNT_NAMES', 'TRIGGER_COUNT_BYTES'):
            with patch.dict(self.namespace, {name: 0}), self.subTest(name=name), self.assertRaisesRegex(ValueError, 'bound'):
                self.plan()

    def test_complete_inventory_baseline_is_rebuilt_before_count_grouping(self):
        values = self.observations(); baseline = self.baseline(values); values[9]['header_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'baseline'):
            self.namespace['trigger_count_plan'](values, baseline, [])

    def test_receipt_requires_both_complete_integer_samples_and_exact_compact_bytes(self):
        inventory, rows = self.plan(); counts = [row['inventory_count'] for row in rows]
        result = self.namespace['trigger_count_receipt'](inventory, rows, counts, counts)
        encoded = json.dumps(result['rows'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['rows_bytes'], result['rows_sha256']), (len(encoded), hashlib.sha256(encoded).hexdigest()))
        for before, after in ((counts[:-1], counts), (counts, [1, 1]), ([True, 2], counts)):
            with self.subTest(before=before, after=after), self.assertRaisesRegex(ValueError, 'samples'):
                self.namespace['trigger_count_receipt'](inventory, rows, before, after)

    def test_every_authority_remains_false_even_when_current_count_correspondence_is_true(self):
        inventory, rows = self.plan(); counts = [row['inventory_count'] for row in rows]
        result = self.namespace['trigger_count_receipt'](inventory, rows, counts, counts)
        self.assertTrue(result['count_inventory_correspondence_observed'])
        self.assertEqual(len(self.namespace['TRIGGER_COUNT_AUTHORITIES']), 19)
        for name in self.namespace['TRIGGER_COUNT_AUTHORITIES']: self.assertIs(result[name], False)


class TriggerCountNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix='s4-count-api-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(directory.cleanup); cls.library = Path(directory.name) / 'count.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=effects.LIBRARY, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library)); cls.namespace = {}
        exec(compile(triggers.emitted(), '<actual-count-library>', 'exec'), cls.namespace)
        cls.lib.rpmtsCreate.restype = C.c_void_p; cls.lib.rpmtsCreate.argtypes = ()
        cls.lib.rpmtsFree.restype = C.c_void_p; cls.lib.rpmtsFree.argtypes = (C.c_void_p,)
        cls.lib.triggerCountModelReset.restype = None; cls.lib.triggerCountModelReset.argtypes = ()
        cls.lib.triggerCountModelQueries.restype = C.c_uint; cls.lib.triggerCountModelQueries.argtypes = ()

    def setUp(self):
        self.lib.triggerCountModelReset(); self.transaction = self.lib.rpmtsCreate()
        self.addCleanup(lambda: self.assertIsNone(self.lib.rpmtsFree(self.transaction)))
        self.api = self.namespace['trigger_count_bind'](self.lib)
        self.rows = [{'name': 'userland', 'inventory_count': 1}, {'name': 'new', 'inventory_count': 0}]

    def sample(self): return self.namespace['trigger_count_sample'](self.api, self.transaction, self.rows)

    def test_actual_owned_name_buffers_and_borrowed_database_produce_exact_positive_and_zero_counts(self):
        first, counts = self.sample(); second, again = self.sample()
        self.assertEqual(first, second); self.assertNotEqual(first, self.transaction)
        self.assertEqual(counts, [1, 0]); self.assertEqual(again, counts)
        self.assertEqual(self.lib.triggerCountModelQueries(), 6)

    def test_missing_or_transaction_alias_database_refuses_before_count_queries(self):
        for flag in ('count_db_null', 'count_db_alias'):
            self.lib.triggerCountModelReset()
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: '1'}), self.assertRaisesRegex(ValueError, 'missing or aliases'):
                self.sample()
            self.assertEqual(self.lib.triggerCountModelQueries(), 0)

    def test_read_only_mode_is_required_before_native_queries(self):
        with patch.dict(os.environ, count_wrong_mode='1'), self.assertRaisesRegex(ValueError, 'read-only'): self.sample()
        self.assertEqual(self.lib.triggerCountModelQueries(), 0)

    def test_null_name_requires_exact_negative_one_before_real_name_queries(self):
        with patch.dict(os.environ, count_null_positive='1'), self.assertRaisesRegex(ValueError, 'NULL-name'): self.sample()
        self.assertEqual(self.lib.triggerCountModelQueries(), 1)

    def test_negative_excessive_or_disagreeing_counts_refuse(self):
        for flag in ('count_negative', 'count_overflow', 'count_mismatch'):
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: '1'}), self.assertRaisesRegex(ValueError, 'complete installed inventory'):
                self.sample()

    def test_changed_caller_name_is_refused_without_native_ownership_transfer(self):
        with patch.dict(os.environ, count_caller_changed='1'), self.assertRaisesRegex(ValueError, 'caller name'): self.sample()

    def test_borrowed_database_must_remain_the_same_after_every_complete_sample(self):
        with patch.dict(os.environ, count_db_changed='1'), self.assertRaisesRegex(ValueError, 'context changed'): self.sample()

    def test_missing_public_symbol_refuses_before_queries(self):
        class Missing:
            def __getattr__(proxy, name):
                if name == 'rpmdbCountPackages': raise AttributeError(name)
                return getattr(self.lib, name)
        with self.assertRaisesRegex(ValueError, 'symbol is missing: rpmdbCountPackages'):
            self.namespace['trigger_count_bind'](Missing())
        self.assertEqual(self.lib.triggerCountModelQueries(), 0)

    def test_unsupported_abi_refuses_before_symbol_binding(self):
        with patch.object(self.namespace['platform'], 'machine', return_value='unsupported'), self.assertRaisesRegex(ValueError, 'ABI'):
            self.namespace['trigger_count_bind'](None)


class TriggerCountProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof

    def observe(self, proof):
        return self.namespace['trigger_count_observe'](self.namespace['trigger_observe'](proof))['trigger_count_observation']

    def test_no_ordinary_triggers_still_require_complete_current_count_receipt(self):
        proof = self.proof(trigger=False); result = self.observe(proof)
        self.assertEqual([(row['name'], row['native_before']) for row in result['rows']], [('fixture', 1), ('future', 0)])
        self.assertFalse(proof['header_iteration_observation']['native_iterator_correspondence_observed'])

    def test_missing_raw_counts_cannot_borrow_a_stale_successful_observation(self):
        proof = self.proof(trigger=False); del proof['effects']['installed_name_counts']
        proof['trigger_count_observation'] = {'count_inventory_correspondence_observed': True}
        with self.assertRaises(KeyError): self.observe(proof)

    def test_partial_reordered_or_modified_rows_withhold_the_complete_result(self):
        for change in ('partial', 'order', 'count', 'instance', 'file', 'hash'):
            proof = self.proof(trigger=False); raw = proof['effects']['installed_name_counts']
            if change == 'partial': raw['rows'].pop()
            elif change == 'order': raw['rows'].reverse()
            elif change == 'count': raw['rows'][0]['native_after'] += 1
            elif change == 'instance': raw['rows'][0]['installed_instances'] = [99]
            elif change == 'file': raw['rows'][1]['incoming_files'] = []
            else: raw['rows_sha256'] = 'a' * 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'raw native receipt'): self.observe(proof)

    def test_boolean_integer_receipts_and_nested_instance_aliases_refuse(self):
        for change in ('schema', 'count', 'instance'):
            proof = self.proof(trigger=False); raw = proof['effects']['installed_name_counts']
            if change == 'schema': raw['schema'] = True
            elif change == 'count': raw['rows'][0]['native_before'] = True
            else: raw['rows'][0]['installed_instances'] = [True]
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'raw native receipt'): self.observe(proof)

    def test_true_or_numeric_authority_is_not_admitted_as_false(self):
        for value in (True, 0):
            proof = self.proof(trigger=False); proof['effects']['installed_name_counts']['script_arguments_selected'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'raw native receipt'): self.observe(proof)


class TriggerCountPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputPrivateTests.setUpClass.__func__)
    setUp = headers.HeaderInputPrivateTests.setUp
    proof = triggers.TriggerProofTests.proof
    rebind = providers.ProviderProofTests.rebind
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    make_proof = headers.HeaderInputProofTests.make_proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_owned_private_input_binds_all_twelve_hashes_without_modification(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_raw_count_delivery_with_stale_success_refuses_zero_json_and_keeps_input(self):
        proof = json.loads(self.path.read_text()); del proof['effects']['installed_name_counts']
        proof['trigger_count_observation'] = {'count_inventory_correspondence_observed': True}
        self.path.write_text(json.dumps(proof, sort_keys=True) + '\n'); before = self.path.read_bytes()
        result = self.run_guard(expected=75)
        self.assertIn('installed_name_counts', result.stderr); self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), before)


class TriggerCountPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_binds_before_after_counts_all_twelve_hashes_and_preserves_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        observed = proof['trigger_count_observation']; self.assertEqual([(row['name'], row['native_before'], row['native_after'])
            for row in observed['rows']], [('userland', 1, 1)])
        raw = copy.deepcopy(proof)
        for name in sources.RECEIPTS: raw.pop(name)
        digest = hashlib.sha256((json.dumps(raw, sort_keys=True) + '\n').encode()).hexdigest()
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], digest)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'finite_model_not_vendor_runtime': True}

    def test_post_test_count_disagreement_refuses_zero_json_and_preserves_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export count_after_test=1; s4_check_update_effects', expected=75)
        self.assertIn('trigger count native result differs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'explicit_current_count_delivery_model': True}

    def test_pre_test_count_error_refuses_before_run_and_keeps_retained_state(self):
        self.prepare(); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export count_negative=1; s4_check_update_effects', expected=75)
        self.assertIn('trigger count native result differs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertNotIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_changed_borrowed_database_across_test_refuses_with_no_json_or_pointer_change(self):
        self.prepare(); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export count_db_after_test=1; s4_check_update_effects', expected=75)
        self.assertIn('borrowed database changes across TEST', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)


if __name__ == '__main__': unittest.main()

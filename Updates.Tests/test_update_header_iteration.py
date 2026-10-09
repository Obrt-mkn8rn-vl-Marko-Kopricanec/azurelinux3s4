import copy
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_first as first
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class HeaderIterationNativeTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    fixture = headers.HeaderInputNativeTests.fixture
    assert_retired = headers.HeaderInputNativeTests.assert_retired

    def setUp(self):
        headers.HeaderInputNativeTests.setUp(self)
        for name in ('headerIterationModelInitCalls', 'headerIterationModelNextCalls'):
            getattr(self.lib, name).restype = C.c_uint; getattr(self.lib, name).argtypes = ()
        self.lib.headerIterationModelReset.restype = None; self.lib.headerIterationModelReset.argtypes = ()
        self.lib.headerIterationModelReset()

    def observe(self): return self.namespace['header_iteration_native']()(*self.fixture())

    def test_two_complete_passes_keep_duplicate_positions_full_flags_and_slots(self):
        result = self.observe()
        self.assertEqual(result, {'passes': 2, 'rows_per_pass': 2, 'initial_index': -1, 'terminal_index': -1,
                                 'native_init_calls': 2, 'native_next_calls': 6})
        self.assertEqual((self.lib.headerIterationModelInitCalls(), self.lib.headerIterationModelNextCalls()), (3, 7))
        self.assertEqual((self.lib.headerModelImported(), self.lib.headerModelDsCreated()), (1, 2))
        self.assert_retired()

    def test_changed_borrowed_initializer_handles_refuse_without_new_ownership_or_double_free(self):
        for fault in ('init-null', 'init-header', 'init-caller', 'init-prior'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'borrowed handle'):
                self.observe()
            self.assertEqual((self.lib.headerModelImported(), self.lib.headerModelDsCreated()), (1, 2)); self.assert_retired()

    def test_initializer_must_actually_reset_the_current_index(self):
        with patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': 'init-index'}), self.assertRaisesRegex(ValueError, 'initial receipt'):
            self.observe()
        self.assert_retired()

    def test_skips_repeats_and_early_termination_refuse_complete_correspondence(self):
        for fault in ('skip', 'repeat', 'early-end'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'position differs'):
                self.observe()
            self.assert_retired()

    def test_end_requires_exact_minus_one_and_reset_index(self):
        for fault in ('end-positive', 'end-wrong'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'terminal receipt'):
                self.observe()
            self.assert_retired()

    def test_second_pass_cannot_borrow_the_first_passing_sequence(self):
        with patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': 'second-skip'}), self.assertRaisesRegex(ValueError, 'position differs'):
            self.observe()
        self.assertEqual(self.lib.headerIterationModelInitCalls(), 3); self.assert_retired()

    def test_successful_next_position_cannot_replace_complete_row_readbacks(self):
        for fault in ('receipt-index', 'row-flags'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'row receipt'):
                self.observe()
            self.assert_retired()

    def test_null_participation_failures_refuse_before_header_allocation(self):
        for fault in ('null-init', 'null-next'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'NULL participation'):
                self.observe()
            self.assertEqual(self.lib.headerModelImported(), 0); self.assert_retired()

    def test_missing_next_symbol_refuses_before_header_allocation(self):
        ordinary = self.namespace['C'].CDLL
        class Missing:
            def __getattr__(proxy, name):
                if name == 'rpmdsNext': raise AttributeError(name)
                return getattr(self.lib, name)
        calls = 0
        def delivered(name, **options):
            nonlocal calls
            if name:
                calls += 1
                if calls == 2: return Missing()
            return ordinary(name, **options)
        with patch.object(self.namespace['C'], 'CDLL', staticmethod(delivered)), self.assertRaisesRegex(ValueError, 'symbol is missing: rpmdsNext'):
            self.observe()
        self.assertEqual(self.lib.headerModelImported(), 0); self.assert_retired()

    def test_existing_checked_cleanup_failure_cannot_publish_iterator_success(self):
        for fault in ('ds-free', 'header-free'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'cleanup failed'):
                self.observe()
            self.assert_retired()


class HeaderIterationProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    make_proof = first.TriggerFirstProofTests.make_proof

    def observe(self, proof, factory=None):
        return self.namespace['header_iteration_observe'](self.namespace['trigger_observe'](proof),
            factory or self.namespace['header_iteration_native'], lambda: self.native_compare)['header_iteration_observation']

    def test_complete_ordinary_owner_keeps_original_positions_and_same_input_commitments(self):
        proof = self.make_proof(); before = copy.deepcopy(proof['effects']); result = self.observe(proof)
        self.assertEqual(result['headers_iterated'], 1); self.assertEqual(result['repeated_rows'], 6)
        self.assertEqual(result['owners'][0]['condition_positions'], [0, 1, 2]); self.assertEqual(proof['effects'], before)
        self.assertEqual(result['header_inputs_sha256'], proof['header_input_observation']['owners_sha256'])
        self.assertEqual(result['pair_first_sha256'], proof['trigger_first_observation']['pairs_sha256'])

    def test_ordinary_rows_with_no_matching_source_name_still_have_iterator_correspondence_only(self):
        result = self.observe(self.make_proof(names=(b'absent',) * 3))
        self.assertTrue(result['native_iterator_correspondence_observed']); self.assertFalse(result['trigger_selection_complete'])

    def test_no_ordinary_rows_perform_no_new_factory_or_participation_work(self):
        def forbidden(): self.fail('empty observation loaded the new factory')
        result = self.observe(self.proof(), forbidden)
        self.assertEqual(result['owners'], []); self.assertFalse(result['null_participation_checked'])
        self.assertFalse(result['native_iterator_correspondence_observed']); self.assertEqual(result['repeated_rows'], 0)

    def test_current_raw_exports_are_required_despite_stale_success(self):
        proof = self.make_proof(); del proof['effects']['installed_header_exports']
        proof['header_iteration_observation'] = {'native_iterator_correspondence_observed': True}
        with self.assertRaises(KeyError): self.observe(proof)

    def test_complete_headers_bytes_and_repeated_row_caps_precede_new_factory(self):
        for name in ('HEADER_ITERATION_HEADERS', 'HEADER_ITERATION_BYTES', 'HEADER_ITERATION_ROWS'):
            old = self.namespace[name]; self.namespace[name] = 0
            try:
                def forbidden(): self.fail('new factory ran before admission')
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Header iteration.*bound'): self.observe(self.make_proof(), forbidden)
            finally: self.namespace[name] = old

    def test_incomplete_or_boolean_receipts_refuse_the_entire_observation(self):
        proof = self.make_proof()
        for receipt in ({}, {'passes': True, 'rows_per_pass': 3, 'initial_index': -1, 'terminal_index': -1, 'native_init_calls': 2, 'native_next_calls': 8}):
            with self.subTest(receipt=receipt), self.assertRaisesRegex(ValueError, 'complete receipt'):
                self.observe(copy.deepcopy(proof), lambda: lambda *args: receipt)

    def test_all_nineteen_authorities_remain_false_after_actual_model_iteration(self):
        result = self.observe(self.make_proof())
        self.assertEqual(sum(value is False for value in result.values()), 19)
        self.assertFalse(result['database_temporal_state_observed']); self.assertFalse(result['script_slot_state_observed'])

    def test_entire_owner_receipt_has_exact_compact_ascii_size_and_digest(self):
        result = self.observe(self.make_proof()); data = json.dumps(result['owners'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['owners_bytes'], result['owners_sha256']), (len(data), hashlib.sha256(data).hexdigest()))


class HeaderIterationPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputPrivateTests.setUpClass.__func__)
    setUp = headers.HeaderInputPrivateTests.setUp
    make_proof = headers.HeaderInputProofTests.make_proof
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_real_private_snapshot_binds_all_eleven_receipts_and_preserves_input(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertTrue(proof['header_iteration_observation']['native_iterator_correspondence_observed']); self.assertEqual(self.path.read_bytes(), before)

    def test_native_terminal_fault_on_owned_snapshot_withholds_json_and_preserves_bytes(self):
        before = self.path.read_bytes()
        with patch.dict(os.environ, {'S4_HEADER_ITERATION_MODEL_FAULT': 'end-positive'}): result = self.run_guard(expected=75)
        self.assertIn('Header iteration terminal receipt differs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), before)


class HeaderIterationPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_current_test_native_iterator_receipt_binds_same_header_and_eleven_original_hashes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['header_iteration_observation']; self.assertEqual(receipt['headers_iterated'], 1)
        self.assertEqual(receipt['repeated_rows'], 2); self.assertEqual(receipt['owners'][0]['condition_positions'], [0])
        self.assertEqual(receipt['owners'][0]['native_next_calls'], 4); self.assertEqual(receipt['owners'][0]['passes'], 2)
        raw = copy.deepcopy(proof)
        for name in sources.RECEIPTS: raw.pop(name)
        digest = hashlib.sha256((json.dumps(raw, sort_keys=True) + '\n').encode()).hexdigest()
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], digest)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'finite_model_not_vendor_runtime': True}

    def test_iterator_wrong_terminal_after_current_test_refuses_zero_json_and_preserves_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export S4_HEADER_ITERATION_MODEL_FAULT=end-positive; s4_check_update_effects', expected=75)
        self.assertIn('Header iteration terminal receipt differs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(), 'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'explicit_native_iterator_delivery_model': True}


if __name__ == '__main__': unittest.main()

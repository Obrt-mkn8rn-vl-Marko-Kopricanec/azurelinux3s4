import copy
import ctypes as C
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_first as firsts
import test_update_trigger_sources as sources
import test_update_triggers as triggers

MODEL = Path(__file__).with_name('rpm_trigger_arguments_model.c')


class TriggerArgumentCaseTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def first(self, match=True, marked=False):
        return {'condition_position': 7 if match else None, 'script_index': 2 if match else None,
            'would_enter_unmarked_slot_branch': bool(match and not marked),
            'pair_scan_stops_at_first_match': match}

    def case(self, route='database', correction=-1, target=3, source=2, match=True, marked=False):
        return self.namespace['trigger_argument_case'](self.first(match, marked), target, source, correction, route)

    def test_database_route_corrects_source_arg2_but_not_target_arg1(self):
        result = self.case(); self.assertEqual((result['conditional_arg1'], result['conditional_arg2']), (3, 1))
        self.assertTrue(result['would_pass_source_count_gate']); self.assertFalse(result['fresh_iterator_count_required'])

    def test_negative_corrected_source_stops_database_route_before_target_query(self):
        result = self.case(source=0)
        self.assertFalse(result['would_pass_source_count_gate']); self.assertFalse(result['would_query_target_count'])
        self.assertIsNone(result['conditional_arg1']); self.assertIsNone(result['conditional_arg2'])

    def test_zero_corrected_source_still_passes_the_source_gate(self):
        result = self.case(source=1); self.assertTrue(result['would_reach_script_call'])
        self.assertEqual(result['conditional_arg2'], 0)

    def test_immediate_route_corrects_target_without_guarding_corrected_negative_one(self):
        result = self.case('immediate', target=0, source=0)
        self.assertEqual(result['conditional_arg1'], -1); self.assertTrue(result['would_reach_script_call'])
        self.assertIsNone(result['would_pass_source_count_gate'])

    def test_immediate_arg2_is_unknown_even_with_a_nonzero_current_source_name_count(self):
        result = self.case('immediate', source=32768)
        self.assertIsNone(result['conditional_arg2']); self.assertTrue(result['fresh_iterator_count_required'])

    def test_marked_immediate_first_match_never_queries_counts_or_falls_back(self):
        result = self.case('immediate', marked=True)
        self.assertEqual((result['condition_position'], result['script_index']), (7, 2))
        self.assertFalse(result['would_query_target_count']); self.assertFalse(result['would_reach_script_call'])
        self.assertIsNone(result['conditional_arg1']); self.assertFalse(result['fresh_iterator_count_required'])

    def test_no_match_preserves_absence_without_argument_or_target_query_claims(self):
        for route in ('database', 'immediate'):
            result = self.case(route, match=False)
            self.assertIsNone(result['conditional_arg1']); self.assertIsNone(result['conditional_arg2'])
            self.assertFalse(result['would_query_target_count']); self.assertFalse(result['would_reach_script_call'])

    def test_counts_corrections_and_routes_refuse_bool_or_unsupported_forms(self):
        for arguments in ({'target': True}, {'source': -1}, {'source': 32769}, {'correction': False},
                          {'correction': 1}, {'route': 'runtime'}, {'target': '1'}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError): self.case(**arguments)

    def test_entire_first_case_is_typed_and_coherent_before_arithmetic(self):
        for field, value in (('condition_position', True), ('script_index', 8192),
                             ('pair_scan_stops_at_first_match', 1), ('would_enter_unmarked_slot_branch', 0)):
            value_first = self.first(); value_first[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.namespace['trigger_argument_case'](value_first, 1, 1, 0, 'immediate')
        with self.assertRaises(ValueError): self.case(marked=True)
        value_first = self.first(False); value_first['script_index'] = 0
        with self.assertRaises(ValueError): self.namespace['trigger_argument_case'](value_first, 1, 1, 0, 'immediate')

    def test_profile_boundary_counts_remain_exact_and_do_not_overflow_signed_int(self):
        result = self.case(correction=0, target=32768, source=32768)
        self.assertEqual((result['conditional_arg1'], result['conditional_arg2']), (32768, 32768))


class TriggerArgumentModelTests(unittest.TestCase):
    first = TriggerArgumentCaseTests.first
    case = TriggerArgumentCaseTests.case

    @classmethod
    def setUpClass(cls):
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
        temporary = tempfile.TemporaryDirectory(prefix='s4-trigger-arguments-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.path = Path(temporary.name) / 'model.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.path)],
            input=MODEL.read_text(), text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.path)); cls.lib.triggerArgumentModel.restype = C.c_int
        cls.lib.triggerArgumentModel.argtypes = (C.c_int,) * 6 + (C.POINTER(C.c_int),) * 2

    def model(self, route, correction, target, source, match, marked):
        arg1, arg2 = C.c_int(), C.c_int()
        result = self.lib.triggerArgumentModel(route == 'immediate', correction, target, source,
                                               match, marked, C.byref(arg1), C.byref(arg2))
        return result, (None if arg1.value == -2**31 else arg1.value), (None if arg2.value == -2**31 else arg2.value)

    def test_reduced_c_oracle_matches_both_routes_corrections_counts_and_first_marks(self):
        comparisons = 0
        for route in ('database', 'immediate'):
            for correction in (-1, 0):
                for target in (0, 1, 2, 32768):
                    for source in (0, 1, 2, 32768):
                        for match in (False, True):
                            for marked in ((False, True) if match and route == 'immediate' else (False,)):
                                result = self.case(route, correction, target, source, match, marked)
                                code, arg1, arg2 = self.model(route, correction, target, source, match, marked)
                                with self.subTest(route=route, correction=correction, target=target, source=source, match=match, marked=marked):
                                    self.assertEqual((arg1, arg2), (result['conditional_arg1'], result['conditional_arg2']))
                                    self.assertEqual(bool(code & 1), result['would_reach_script_call'])
                                    self.assertEqual(bool(code & 2), result['fresh_iterator_count_required'])
                                comparisons += 1
        self.assertEqual(comparisons, 160)
        self.record = {'finite_oracle_comparisons': comparisons, 'vendor_execution': False,
                       'no_database_script_or_process_in_oracle': True}

    def test_oracle_preserves_unknown_iterator_and_literal_negative_target_argument(self):
        self.assertEqual(self.model('immediate', -1, 0, 32768, True, False), (3, -1, None))
        self.assertEqual(self.model('database', -1, 32768, 0, True, False), (0, None, None))


class TriggerArgumentProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    make_proof = firsts.TriggerFirstProofTests.make_proof

    def observe(self, proof):
        return self.namespace['trigger_argument_observe'](self.namespace['trigger_observe'](proof),
            comparator_factory=lambda: self.native_compare)['trigger_argument_observation']

    def test_complete_current_count_rows_and_header_owners_bind_each_conditional_pair(self):
        proof = self.make_proof(); result = self.observe(proof); pair = result['pairs'][0]
        self.assertEqual((pair['target_current_count_row']['name'], pair['source_current_count_row']['name']), ('fixture', 'fixture'))
        self.assertEqual(pair['target_current_count_row']['installed_instances'], [1])
        self.assertEqual((result['first_pairs_sha256'], result['count_rows_sha256']),
            (proof['trigger_first_observation']['pairs_sha256'], proof['trigger_count_observation']['rows_sha256']))

    def test_each_phase_retains_both_corrections_without_selecting_a_goal(self):
        result = self.observe(self.make_proof())
        self.assertEqual([(p['phase_mask'], p['phase']) for p in result['pairs'][0]['hypothetical_phases']],
                         list(self.namespace['TRIGGER_SOURCE_PHASES']))
        for phase in result['pairs'][0]['hypothetical_phases']:
            self.assertEqual([row['count_correction'] for row in phase['hypothetical_corrections']], [-1, 0])

    def test_marked_first_match_keeps_original_position_without_fallback_or_arguments(self):
        row = self.observe(self.make_proof())['pairs'][0]['hypothetical_phases'][0]['hypothetical_corrections'][0]
        marked = row['immediate_if_first_marked']; self.assertEqual(marked['condition_position'], 0)
        self.assertFalse(marked['would_reach_script_call']); self.assertIsNone(marked['conditional_arg1'])

    def test_empty_or_no_same_name_pairs_withhold_positive_forecast_facts(self):
        for proof in (self.proof(trigger=False), self.make_proof(names=(b'absent',) * 3)):
            result = self.observe(proof); self.assertEqual(result['pairs'], [])
            self.assertEqual(result['hypothetical_argument_cases'], 0); self.assertFalse(result['conditional_arguments_forecast'])

    def test_missing_raw_count_receipt_refuses_even_with_stale_argument_success(self):
        proof = self.make_proof(); del proof['effects']['installed_name_counts']
        proof['trigger_argument_observation'] = {'conditional_arguments_forecast': True}
        with self.assertRaises(KeyError): self.observe(proof)

    def test_modified_raw_count_cannot_supply_a_conditional_argument(self):
        proof = self.make_proof(); proof['effects']['installed_name_counts']['rows'][0]['native_after'] += 1
        with self.assertRaisesRegex(ValueError, 'raw native receipt'): self.observe(proof)

    def test_new_case_admission_precedes_new_construction_after_inherited_native_work(self):
        with patch.dict(self.namespace, TRIGGER_ARGUMENT_CASES=0), patch.dict(self.namespace, trigger_argument_case=None):
            with self.assertRaisesRegex(ValueError, 'hypothetical cases exceed'): self.observe(self.make_proof())

    def test_complete_serialization_bound_and_digest_are_checked(self):
        proof = self.make_proof(); result = self.observe(proof)
        encoded = json.dumps(result['pairs'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['pairs_bytes'], result['pairs_sha256']), (len(encoded), hashlib.sha256(encoded).hexdigest()))
        with patch.dict(self.namespace, TRIGGER_ARGUMENT_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization bound'):
            self.observe(self.make_proof())

    def test_every_authority_stays_false_and_current_effects_remain_byte_equivalent(self):
        proof = self.make_proof(); before = copy.deepcopy(proof['effects']); result = self.observe(proof)
        self.assertEqual(proof['effects'], before); self.assertEqual(len(self.namespace['TRIGGER_ARGUMENT_AUTHORITIES']), 23)
        for name in self.namespace['TRIGGER_ARGUMENT_AUTHORITIES']: self.assertIs(result[name], False)


class TriggerArgumentPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputPrivateTests.setUpClass.__func__)
    setUp = headers.HeaderInputPrivateTests.setUp
    make_proof = headers.HeaderInputProofTests.make_proof
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_owned_snapshot_binds_all_thirteen_hashes_without_modification(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        self.assertEqual(len(sources.RECEIPTS), 20)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.path.read_bytes(), before)

    def test_actual_private_case_bound_refuses_no_json_and_preserves_raw_input(self):
        before = self.path.read_bytes(); original = self.program.read_text()
        model = original.replace('TRIGGER_ARGUMENT_CASES = 65536', 'TRIGGER_ARGUMENT_CASES = 0')
        self.assertNotEqual(model, original); self.program.write_text(model)
        result = self.run_guard(expected=75)
        self.assertIn('trigger argument hypothetical cases exceed their bound', result.stderr)
        self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), before)


class TriggerArgumentPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_forecasts_both_routes_without_substituting_current_counts_for_iterator(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_argument_observation']; self.assertEqual(receipt['header_name_candidate_pairs'], 2)
        row = receipt['pairs'][1]['hypothetical_phases'][0]['hypothetical_corrections'][0]
        self.assertEqual((row['database_if_unmarked']['conditional_arg1'], row['database_if_unmarked']['conditional_arg2']), (1, 0))
        self.assertEqual(row['immediate_if_unmarked']['conditional_arg1'], 0)
        self.assertIsNone(row['immediate_if_unmarked']['conditional_arg2'])
        self.assertTrue(row['immediate_if_unmarked']['fresh_iterator_count_required'])
        self.assertFalse(row['immediate_if_first_marked']['would_reach_script_call'])
        self.assertIn('run 1', self.native_calls())
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        for name in ('script_arguments_selected', 'count_correction_selected', 'iterator_cardinality_observed',
                     'runtime_script_arguments_observed', 'trigger_eligibility_complete'):
            self.assertIs(receipt[name], False)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'native_test_seen': True, 'ordinary_cleanup_verified': True, 'finite_model_not_vendor_runtime': True}

    def test_hypothetical_case_bound_refuses_after_current_test_zero_json_and_keeps_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        program = triggers.emitted()
        model = program.replace('TRIGGER_ARGUMENT_CASES = 65536', 'TRIGGER_ARGUMENT_CASES = 0').replace(
            'C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        self.assertNotEqual(model, program); model_path = self.root / 'argument-bound-model.py'; model_path.write_text(model)
        import shlex
        result = self.shell('s4_update_trigger_inputs_program() { cat ' + shlex.quote(str(model_path)) + '; }; s4_check_update_effects', expected=75)
        self.assertIn('trigger argument hypothetical cases exceed their bound', result.stderr)
        self.assertEqual(result.stdout, ''); self.assertIn('run 1', self.native_calls())
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'native_test_seen': True, 'ordinary_cleanup_verified': True, 'explicit_bound_delivery_model': True}


if __name__ == '__main__': unittest.main()

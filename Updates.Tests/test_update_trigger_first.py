import copy
import ctypes as C
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_sources as sources
import test_update_triggers as triggers

MODEL = Path(__file__).with_name('rpm_trigger_first_model.c')


class TriggerFirstCaseTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def rows(self, phases=(65536, 65536, 65536), slots=(1, 0, 1), positives=(True, True, True)):
        return [dict(condition_position=position, script_index=slot, declared_sense=phase,
                     captured_header_dependency_match=positive)
                for position, (phase, slot, positive) in enumerate(zip(phases, slots, positives))]

    def case(self, rows=None, phase=65536, marked=()):
        return self.namespace['trigger_first_case'](self.rows() if rows is None else rows, phase, marked)

    def test_first_positive_uses_condition_position_not_lowest_script_slot(self):
        self.assertEqual(self.case(), {'condition_position': 0, 'script_index': 1,
            'would_enter_unmarked_slot_branch': True, 'pair_scan_stops_at_first_match': True})

    def test_marked_first_slot_stops_pair_without_falling_back_to_later_unmarked_slot(self):
        result = self.case(marked=(1,))
        self.assertEqual((result['condition_position'], result['script_index']), (0, 1))
        self.assertFalse(result['would_enter_unmarked_slot_branch']); self.assertTrue(result['pair_scan_stops_at_first_match'])

    def test_unrelated_mark_does_not_suppress_the_first_matching_slot(self):
        self.assertTrue(self.case(marked=(0,))['would_enter_unmarked_slot_branch'])

    def test_wrong_phase_and_negative_header_results_are_skipped_before_first_match(self):
        result = self.case(self.rows(phases=(131072, 65536, 65536), positives=(True, False, True)))
        self.assertEqual((result['condition_position'], result['script_index']), (2, 1))

    def test_each_supported_phase_has_its_own_conditional_first_position(self):
        phases = tuple(mask for mask, _ in self.namespace['TRIGGER_SOURCE_PHASES'])
        rows = self.rows(phases=phases, slots=(3, 2, 1, 0), positives=(True,) * 4)
        for position, phase in enumerate(phases):
            with self.subTest(phase=phase):
                result = self.case(rows, phase); self.assertEqual(result['condition_position'], position)

    def test_empty_and_all_negative_cases_have_no_slot_or_break_claim(self):
        for rows in ([], self.rows(positives=(False, False, False))):
            with self.subTest(rows=rows): self.assertEqual(self.case(rows), {'condition_position': None,
                'script_index': None, 'would_enter_unmarked_slot_branch': False, 'pair_scan_stops_at_first_match': False})

    def test_nonconsecutive_original_positions_and_high_sense_bits_are_preserved(self):
        rows = self.rows(); rows[0]['condition_position'] = 2; rows[1]['condition_position'] = 7; rows[2]['condition_position'] = 11
        rows[0]['declared_sense'] |= 1 << 31
        self.assertEqual(self.case(rows)['condition_position'], 2)

    def test_duplicate_or_reversed_positions_refuse_even_after_an_early_positive(self):
        for position in (0, -1):
            rows = self.rows(); rows[1]['condition_position'] = position
            with self.subTest(position=position), self.assertRaisesRegex(ValueError, 'unsupported or unordered'): self.case(rows)

    def test_bool_nonboolean_query_and_out_of_profile_indexes_refuse(self):
        for field, value in (('condition_position', True), ('condition_position', 65536), ('script_index', 8192),
                             ('script_index', False), ('declared_sense', True), ('captured_header_dependency_match', 1)):
            rows = self.rows(); rows[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.case(rows)

    def test_missing_extra_fields_and_combined_phase_declarations_refuse(self):
        rows = self.rows(); del rows[0]['script_index']
        with self.assertRaises(ValueError): self.case(rows)
        rows = self.rows(); rows[0]['extra'] = True
        with self.assertRaises(ValueError): self.case(rows)
        rows = self.rows(); rows[0]['declared_sense'] |= 131072
        with self.assertRaises(ValueError): self.case(rows)

    def test_unsupported_phase_or_mark_forms_refuse_without_normalization(self):
        for phase in (True, 0, 65536 | 131072, 1 << 31):
            with self.subTest(phase=phase), self.assertRaises(ValueError): self.case(phase=phase)
        for marked in ([1], (True,), (-1,), (8192,), (1, 1)):
            with self.subTest(marked=marked), self.assertRaises(ValueError): self.case(marked=marked)

    def test_row_cap_refuses_the_complete_case_before_selection(self):
        old = self.namespace['TRIGGER_FIRST_PAIR_LIMIT']; self.namespace['TRIGGER_FIRST_PAIR_LIMIT'] = 2
        try:
            with self.assertRaisesRegex(ValueError, 'rows/marks'): self.case()
        finally: self.namespace['TRIGGER_FIRST_PAIR_LIMIT'] = old


class TriggerFirstModelTests(unittest.TestCase):
    rows = TriggerFirstCaseTests.rows
    case = TriggerFirstCaseTests.case

    @classmethod
    def setUpClass(cls):
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
        temporary = tempfile.TemporaryDirectory(prefix='s4-trigger-first-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.path = Path(temporary.name) / 'model.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.path)], input=MODEL.read_text(),
                       text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.path)); cls.lib.triggerFirstModel.restype = None
        cls.lib.triggerFirstModel.argtypes = (C.c_uint, C.POINTER(C.c_uint32), C.POINTER(C.c_uint32),
            C.POINTER(C.c_uint32), C.POINTER(C.c_int), C.c_uint32, C.c_uint32, C.c_uint, C.c_uint,
            C.POINTER(C.c_uint32), C.POINTER(C.c_uint32), C.POINTER(C.c_uint))

    def model(self, rows, phase, marked=(), omit=False):
        arrays = [(C.c_uint32 * len(rows))(*(row[key] for row in rows))
                  for key in ('condition_position', 'declared_sense', 'script_index')]
        results = (C.c_int * len(rows))(*(int(row['captured_header_dependency_match']) for row in rows))
        before = tuple(bytes(array) for array in (*arrays, results)); position, slot, enter = C.c_uint32(), C.c_uint32(), C.c_uint()
        self.lib.triggerFirstModel(len(rows), *arrays, results, phase, marked[0] if marked else 0,
                                   bool(marked), omit, C.byref(position), C.byref(slot), C.byref(enter))
        self.assertEqual(tuple(bytes(array) for array in (*arrays, results)), before)
        return {'condition_position': None if position.value == 2**32-1 else position.value,
            'script_index': None if slot.value == 2**32-1 else slot.value,
            'would_enter_unmarked_slot_branch': bool(enter.value), 'pair_scan_stops_at_first_match': position.value != 2**32-1}

    def test_reduced_c_model_matches_each_phase_and_marked_first_case(self):
        rows = self.rows(); rows[0]['declared_sense'] = 131072; rows[1]['captured_header_dependency_match'] = False
        for phase, _ in self.namespace['TRIGGER_SOURCE_PHASES']:
            for marked in ((), (1,)):
                with self.subTest(phase=phase, marked=marked): self.assertEqual(self.model(rows, phase, marked), self.case(rows, phase, marked))

    def test_explicit_omitted_break_model_changes_position_and_marked_slot_suppression(self):
        rows = self.rows(slots=(1, 1, 0)); correct = self.case(rows, marked=(1,)); omitted = self.model(rows, 65536, (1,), omit=True)
        self.assertEqual((correct['condition_position'], correct['would_enter_unmarked_slot_branch']), (0, False))
        self.assertEqual((omitted['condition_position'], omitted['would_enter_unmarked_slot_branch']), (2, True))
        self.assertNotEqual(correct, omitted)


class TriggerFirstProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind

    def make_proof(self, names=(b'fixture', b'fixture', b'absent'), phases=(65536,) * 3,
                   versions=(b'',) * 3, masks=(0,) * 3, indexes=(0, 1, 1), provided_version=b''):
        proof = self.proof(); owner = proof['effects']['installed_script_owners'][0]
        entries = triggers.trigger_entries('trigger', indexes=indexes, senses=tuple(phase | mask for phase, mask in zip(phases, masks)))
        entries = [(tag, kind, list(names) if tag == 1066 else list(versions) if tag == 1067 else values) for tag, kind, values in entries]
        entries += headers.providers.provides.entries((b'fixture',), (provided_version,), (8 if provided_version else 0,))
        material = headers.effects.exported(entries); audited = self.namespace['audit_header'](material)
        owner.update(audited, provides=self.namespace['provides_export'](material, audited),
            trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited),
            file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps([(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        self.rebind(proof)
        proof['effects']['installed_header_exports'] = [{**proof['effects']['installed_versions']['entries'][0], 'header_export_hex': material.hex()}]
        proof['effects']['incoming'][0]['header_export_hex'] = headers.effects.exported([(1023, 6, [b'body'])]).hex()
        return proof

    def observe(self, proof):
        return self.namespace['trigger_first_observe'](self.namespace['trigger_observe'](proof),
            self.namespace['header_match_native'], lambda: self.native_compare)['trigger_first_observation']

    def test_first_positive_has_same_header_pair_and_four_hypothetical_phases(self):
        record = self.observe(self.make_proof()); self.assertEqual(record['header_name_candidate_pairs'], 1)
        self.assertEqual(record['hypothetical_phase_cases'], 4); pair = record['pairs'][0]
        self.assertEqual(pair['name_candidate_condition_positions'], [0, 1])
        phase = pair['hypothetical_phases'][0]; self.assertEqual(phase['if_no_slots_marked']['condition_position'], 0)
        self.assertFalse(phase['if_first_matching_slot_marked']['would_enter_unmarked_slot_branch'])

    def test_native_negative_before_positive_selects_later_position_only_conditionally(self):
        record = self.observe(self.make_proof(versions=(b'99-1', b'1-1', b''), masks=(8, 8, 0), provided_version=b'1-1'))
        self.assertEqual(record['pairs'][0]['hypothetical_phases'][0]['if_no_slots_marked']['condition_position'], 1)

    def test_wrong_phase_before_positive_does_not_consume_the_later_phase_slot(self):
        record = self.observe(self.make_proof(phases=(131072, 65536, 65536)))
        self.assertEqual([phase['if_no_slots_marked']['condition_position'] for phase in record['pairs'][0]['hypothetical_phases']], [1, 0, None, None])

    def test_source_name_mismatch_preserves_nonconsecutive_original_position(self):
        record = self.observe(self.make_proof(names=(b'absent', b'fixture', b'absent')))
        self.assertEqual(record['pairs'][0]['name_candidate_condition_positions'], [1])
        self.assertEqual(record['pairs'][0]['hypothetical_phases'][0]['if_no_slots_marked']['condition_position'], 1)

    def test_no_ordinary_or_same_name_pairs_withhold_forecast_facts(self):
        for proof in (self.proof(), self.make_proof(names=(b'absent',) * 3)):
            record = self.observe(proof); self.assertEqual(record['pairs'], [])
            self.assertFalse(record['hypothetical_pair_first_observed']); self.assertEqual(record['hypothetical_phase_cases'], 0)

    def test_missing_raw_exports_refuse_even_with_stale_positive_first_receipt(self):
        proof = self.make_proof(); del proof['effects']['installed_header_exports']
        proof['trigger_first_observation'] = {'hypothetical_pair_first_observed': True}
        with self.assertRaises(KeyError): self.observe(proof)

    def test_pair_phase_and_work_bounds_refuse_after_accepted_header_queries(self):
        for name in ('TRIGGER_FIRST_PAIR_LIMIT', 'TRIGGER_FIRST_PHASE_LIMIT', 'TRIGGER_FIRST_ROW_WORK'):
            old = self.namespace[name]; self.namespace[name] = 0
            try:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'trigger first.*bound'): self.observe(self.make_proof())
            finally: self.namespace[name] = old

    def test_unchanged_input_and_all_eighteen_authorities_withhold_runtime_selection(self):
        proof = self.make_proof(); before = copy.deepcopy(proof['effects']); record = self.observe(proof)
        self.assertEqual(proof['effects'], before); self.assertEqual(sum(value is False for value in record.values()), 18)
        self.assertFalse(record['script_slot_state_observed']); self.assertFalse(record['database_temporal_state_observed'])

    def test_complete_pair_commitment_binds_native_query_and_condition_commitments(self):
        proof = self.make_proof(); record = self.observe(proof)
        data = json.dumps(record['pairs'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((record['pairs_bytes'], record['pairs_sha256']), (len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual(record['header_matches_sha256'], proof['header_match_observation']['pairs_sha256'])
        self.assertEqual(record['source_conditions_sha256'], proof['trigger_source_observation']['conditions_sha256'])


class TriggerFirstPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputPrivateTests.setUpClass.__func__)
    setUp = headers.HeaderInputPrivateTests.setUp
    make_proof = headers.HeaderInputProofTests.make_proof
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_real_private_snapshot_binds_all_ten_receipts_without_changing_input(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(proof['trigger_first_observation']['header_name_candidate_pairs'], 1)
        self.assertEqual(self.path.read_bytes(), before)

    def test_actual_private_first_bound_refuses_exactly_without_json(self):
        before = self.path.read_bytes(); program = self.program.read_text().replace('TRIGGER_FIRST_ROW_WORK = 131072', 'TRIGGER_FIRST_ROW_WORK = 0')
        self.assertNotEqual(program, self.program.read_text()); self.program.write_text(program)
        result = self.run_guard(expected=75); self.assertIn('trigger first hypothetical row work exceeds its bound', result.stderr)
        self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), before)


class TriggerFirstPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_pair_first_forecast_preserves_two_unselected_source_headers(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_first_observation']; self.assertEqual(receipt['header_name_candidate_pairs'], 2)
        self.assertEqual(receipt['hypothetical_phase_cases'], 8)
        self.assertEqual([(pair['source_owner']['kind'], pair['hypothetical_phases'][0]['if_no_slots_marked']['condition_position']) for pair in receipt['pairs']], [('installed', None), ('incoming', 0)])
        self.assertFalse(receipt['pairs'][1]['hypothetical_phases'][0]['if_first_matching_slot_marked']['would_enter_unmarked_slot_branch'])
        raw = copy.deepcopy(proof)
        for name in sources.RECEIPTS: raw.pop(name)
        digest = hashlib.sha256((json.dumps(raw, sort_keys=True) + '\n').encode()).hexdigest()
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], digest)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'finite_model_not_vendor_runtime': True}

    def test_first_forecast_bound_after_fresh_test_refuses_without_json_or_pointer_change(self):
        self.prepare(condition_ordinary=True, provider_positive=True)
        import shlex
        program = triggers.emitted().replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',').replace('TRIGGER_FIRST_ROW_WORK = 131072', 'TRIGGER_FIRST_ROW_WORK = 0')
        path = self.root / 'first-bound.py'; path.write_text(program)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        prelude = 's4_update_trigger_inputs_program() { cat -- ' + shlex.quote(str(path)) + '; }; '
        result = self.shell(prelude + 's4_check_update_effects', expected=75)
        self.assertIn('trigger first hypothetical row work exceeds its bound', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(), 'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'explicit_bound_delivery_model': True}


if __name__ == '__main__': unittest.main()

import copy
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_effects as effects
import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_iterators as iterators
import test_update_trigger_sources as sources
import test_update_triggers as triggers

MODEL = Path(__file__).with_name('rpm_trigger_walk_model.c')


class TriggerWalkCaseTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def fixture(self, names=('a', 'a'), slots=(0, 1), phases=(65536, 65536),
                positives=((True, True), (True, True)), order=(1, 2)):
        conditions = [dict(condition_position=i, script_index=slot, name=name, declared_sense=phase)
                      for i, (name, slot, phase) in enumerate(zip(names, slots, phases))]
        source_rows = []
        for instance, positive in enumerate(positives, 1):
            source_rows.append({'owner': {'kind': 'installed', 'instance': instance, 'name': names[0]},
                'rows': [{**{field: row[field] for field in ('condition_position', 'script_index', 'declared_sense')},
                          'captured_header_dependency_match': positive[row['condition_position']]}
                         for row in conditions if row['name'] == names[0]]})
        lookups = {name: {'count': len(order) if name == names[0] else 0,
                         'order': list(order) if name == names[0] else []} for name in names}
        return conditions, source_rows, lookups

    def case(self, fixture=None, phase=65536, correction=-1, target_count=1):
        return self.namespace['trigger_walk_case'](*(self.fixture() if fixture is None else fixture),
                                                  phase, correction, target_count)

    def test_first_marked_match_never_falls_back_to_later_unmarked_slot(self):
        result = self.case()
        self.assertEqual(len(result['conditional_call_attempts']), 1)
        self.assertEqual(result['final_marked_slots'], [0])
        self.assertFalse(result['lookups'][1]['skipped_already_marked'])
        self.assertTrue(all(not visit['would_enter_unmarked_slot_branch'] for visit in result['lookups'][1]['source_visits']))

    def test_different_sources_can_mark_different_slots_inside_one_lookup(self):
        result = self.case(self.fixture(positives=((True, False), (False, True))))
        self.assertEqual([(call['source_owner']['instance'], call['script_index']) for call in result['conditional_call_attempts']], [(1, 0), (2, 1)])
        self.assertTrue(result['lookups'][1]['skipped_already_marked'])
        self.assertEqual(result['lookups'][1]['source_visits'], [])

    def test_native_source_order_is_preserved_and_can_change_the_conditional_first_caller(self):
        first = self.case(); reverse = self.case(self.fixture(order=(2, 1)))
        self.assertEqual(first['conditional_call_attempts'][0]['source_owner']['instance'], 1)
        self.assertEqual(reverse['conditional_call_attempts'][0]['source_owner']['instance'], 2)

    def test_wrong_phase_outer_condition_still_opens_lookup_and_checks_whole_same_name_array(self):
        result = self.case(self.fixture(phases=(131072, 65536)))
        call = result['conditional_call_attempts'][0]
        self.assertEqual((call['lookup_condition_position'], call['condition_position'], call['script_index']), (0, 1, 1))
        self.assertEqual(result['final_marked_slots'], [1])

    def test_literal_negative_target_argument_and_full_current_iterator_cardinality_remain_conditional(self):
        call = self.case(target_count=0)['conditional_call_attempts'][0]
        self.assertEqual((call['conditional_arg1'], call['conditional_arg2']), (-1, 2))
        self.assertEqual(self.case(correction=0, target_count=32768)['conditional_call_attempts'][0]['conditional_arg1'], 32768)

    def test_all_negative_sources_leave_slots_unmarked_and_repeat_name_lookups(self):
        result = self.case(self.fixture(positives=((False, False), (False, False))))
        self.assertEqual(result['conditional_call_attempts'], []); self.assertEqual(result['final_marked_slots'], [])
        self.assertEqual([len(row['source_visits']) for row in result['lookups']], [2, 2])

    def test_absent_names_and_empty_targets_publish_no_conditional_calls(self):
        result = self.case(self.fixture(positives=(), order=()))
        self.assertEqual([row['conditional_iterator_arg2'] for row in result['lookups']], [0, 0])
        self.assertEqual(result['conditional_call_attempts'], [])
        self.assertEqual(self.case(([], [], {})), {'lookups': [], 'conditional_call_attempts': [], 'final_marked_slots': []})

    def test_missing_or_foreign_source_queries_refuse_the_complete_case(self):
        for edit in (lambda f: f[1].pop(), lambda f: f[1][1]['owner'].update(instance=99),
                     lambda f: f[1][1]['owner'].update(name='other'), lambda f: f[1][1]['rows'].pop()):
            fixture = self.fixture(); edit(fixture)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.case(fixture)

    def test_malformed_late_condition_or_query_cannot_borrow_an_early_positive(self):
        for edit in (lambda f: f[0][1].update(condition_position=0), lambda f: f[0][1].update(script_index=True),
                     lambda f: f[1][1]['rows'][1].update(captured_header_dependency_match=1),
                     lambda f: f[1][1]['rows'][1].update(declared_sense=131072)):
            fixture = self.fixture(); edit(fixture)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.case(fixture)

    def test_missing_duplicate_boolean_and_late_lookup_receipts_refuse(self):
        for edit in (lambda f: f[2].clear(), lambda f: f[2]['a'].update(count=True),
                     lambda f: f[2]['a'].update(order=[1, 1]), lambda f: f[2]['a'].update(order=[1, True]),
                     lambda f: f[2].update(unused={'count': 0, 'order': []})):
            fixture = self.fixture(); edit(fixture)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.case(fixture)

    def test_phase_correction_and_count_types_refuse(self):
        for kwargs in ({'phase': True}, {'phase': 0}, {'correction': True}, {'correction': 1},
                       {'target_count': True}, {'target_count': -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): self.case(**kwargs)

    def test_conservative_work_cap_precedes_source_scan_even_when_every_first_slot_would_mark(self):
        with patch.dict(self.namespace, TRIGGER_WALK_WORK=0), self.assertRaisesRegex(ValueError, 'repeated-row work'):
            self.case()


class TriggerWalkLookupTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def owner(self, names=(b'absent', b'fixture', b'absent')):
        material = effects.exported([(1066, 8, list(names)), (1067, 8, [b''] * len(names))])
        audit = self.namespace['audit_header'](material)
        return {**audit, 'trigger_condition_bytes': self.namespace['trigger_condition_export'](material, audit)}

    def test_only_missing_condition_names_need_new_native_lookup_without_fabricating_incoming_files(self):
        result = self.namespace['trigger_walk_lookup_plan']([self.owner()], [{'name': 'fixture'}])
        self.assertEqual(result, [{'name': 'absent', 'installed_instances': [], 'incoming_files': [], 'inventory_count': 0}])

    def test_raw_name_projection_hash_count_order_and_lexical_controls_refuse_before_new_query(self):
        for edit in (lambda o: o['trigger_condition_bytes'][0]['hex_values'].pop(),
                     lambda o: o['trigger_condition_bytes'][0]['hex_values'].__setitem__(0, b'changed'.hex()),
                     lambda o: o['trigger_condition_bytes'].reverse()):
            owner = self.owner(); edit(owner)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.namespace['trigger_walk_lookup_plan']([owner], [])
        with self.assertRaisesRegex(ValueError, 'declared profile'):
            self.namespace['trigger_walk_lookup_plan']([self.owner((b'hostname wildcard',))], [])

    def test_aggregate_condition_name_bound_refuses_even_for_repeated_name(self):
        with patch.dict(self.namespace, TRIGGER_WALK_NAMES=1), self.assertRaisesRegex(ValueError, 'name work'):
            self.namespace['trigger_walk_lookup_plan']([self.owner()], [])

    def test_empty_extra_plan_withholds_new_native_sample_controls_and_positive_observation(self):
        inventory = {'baseline_sha256': 'a' * 64, 'entries_sha256': 'b' * 64}
        result = self.namespace['trigger_walk_lookup_receipt'](inventory, [], [], [])
        self.assertEqual((result['samples'], result['null_controls'], result['new_rpm_api_calls']), (0, 0, 0))
        self.assertFalse(result['condition_name_lookups_observed']); self.assertFalse(result['count_and_complete_traversal_correspondence_observed'])

    def test_actual_null_zero_extra_lookup_uses_accepted_native_ownership_controls(self):
        # A disposable C/library delivery only, without package TEST.
        native = iterators.TriggerIteratorNativeTests('test_actual_name_lookup_count_traversal_export_and_null_zero_lookup_match_complete_inventory')
        native.setUpClass()
        try:
            native.setUp()
            rows = [{'name': 'absent', 'installed_instances': [], 'incoming_files': [], 'inventory_count': 0}]
            database, sample = native.namespace['trigger_iterator_sample'](native.api, native.free, native.transaction, native.inventory, rows)
            self.assertNotEqual(database, native.transaction); self.assertEqual(sample, [{'count_start': 0, 'count_end': 0, 'order': [], 'iterator_present': False}])
            result = self.namespace['trigger_walk_lookup_receipt'](native.inventory, rows, sample, sample)
            self.assertEqual(result['new_rpm_api_calls'], 22); self.assertTrue(result['condition_name_lookups_observed'])
            native.retired(0); self.assertEqual(native.frees, [])
            self.record = {'sample': sample, 'receipt': result, 'package_test_performed': False,
                           'no_export_frees': True, 'native_model_not_vendor_database': True}
        finally:
            native.doCleanups(); native.doClassCleanups()


class TriggerWalkOracleTests(unittest.TestCase):
    fixture = TriggerWalkCaseTests.fixture
    case = TriggerWalkCaseTests.case

    @classmethod
    def setUpClass(cls):
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
        directory = tempfile.TemporaryDirectory(prefix='s4-conditional-walk-oracle-', dir=Path.home() / '.cache')
        cls.addClassCleanup(directory.cleanup); cls.root = Path(directory.name)
        cls.models = []
        for label, options in (('intact', []), ('omit-break', ['-DWALK_OMIT_FIRST_BREAK'])):
            library = cls.root / (label + '.so')
            subprocess.run(['cc', '-shared', '-fPIC', *options, str(MODEL), '-o', str(library)],
                           text=True, capture_output=True, check=True)
            function = C.CDLL(str(library)).triggerWalkModel
            function.restype = C.c_int
            function.argtypes = (C.c_int, C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_uint),
                C.c_int, C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_int),
                C.c_uint, C.c_int, C.c_int, C.POINTER(C.c_int), C.POINTER(C.c_int))
            cls.models.append(function)

    def oracle(self, fixture, phase=65536, correction=-1, target_count=1, omission=False):
        conditions, sources, lookups = fixture
        names = {name: position for position, name in enumerate(sorted(lookups))}
        source_positions = {source['owner']['instance']: i for i, source in enumerate(sources)}
        order = [source_positions[value] for name in sorted(lookups) for value in lookups[name]['order']]
        matrix = []
        for source in sources:
            query = {row['condition_position']: row['captured_header_dependency_match'] for row in source['rows']}
            matrix.extend(int(query.get(i, False)) for i in range(len(conditions)))
        integer = lambda values: (C.c_int * max(1, len(values)))(*values)
        calls, marked = (C.c_int * 640)(), C.c_int()
        count = self.models[omission](len(conditions), integer([names[row['name']] for row in conditions]),
            integer([row['script_index'] for row in conditions]),
            (C.c_uint * max(1, len(conditions)))(*[row['declared_sense'] for row in conditions]),
            len(sources), integer([names[row['owner']['name']] for row in sources]), integer(order), integer(matrix),
            phase, correction, target_count, calls, C.byref(marked))
        self.assertGreaterEqual(count, 0)
        return [list(calls[5 * i:5 * i + 5]) for i in range(count)], [slot for slot in range(16) if marked.value & (1 << slot)]

    def test_finite_c_oracle_agrees_on_orders_all_phases_corrections_counts_and_match_matrices(self):
        comparisons = 0
        for bits, order, phase, correction, target in itertools.product(itertools.product((False, True), repeat=4),
                ((1, 2), (2, 1)), (65536, 131072, 262144, 33554432), (-1, 0), (0, 1)):
            fixture = self.fixture(phases=(65536, 131072), positives=(bits[:2], bits[2:]), order=order)
            result = self.case(fixture, phase, correction, target)
            expected = [[row['lookup_condition_position'], row['source_owner']['instance'] - 1, row['script_index'],
                         row['conditional_arg1'], row['conditional_arg2']] for row in result['conditional_call_attempts']]
            with self.subTest(bits=bits, order=order, phase=phase, correction=correction, target=target):
                self.assertEqual(self.oracle(fixture, phase, correction, target), (expected, result['final_marked_slots']))
            comparisons += 1
        self.assertEqual(comparisons, 512)
        self.record = {'finite_oracle_comparisons': comparisons, 'vendor_execution': False,
                       'no_database_script_or_process_in_oracle': True}

    def test_precise_omit_break_model_exposes_unshipped_later_slot_fallback(self):
        fixture = self.fixture(positives=((True, True),), order=(1,))
        normal = self.oracle(fixture); omitted = self.oracle(fixture, omission=True)
        self.assertEqual(normal, ([[0, 0, 0, 0, 1]], [0]))
        self.assertEqual(omitted, ([[0, 0, 0, 0, 1], [0, 0, 1, 0, 1]], [0, 1]))
        self.assertEqual(self.case(fixture)['final_marked_slots'], normal[1])
        self.record = {'intact_finite_oracle': normal, 'explicit_omit_break_model': omitted,
                       'no_shipped_control_omitted': True, 'vendor_execution': False}


class TriggerWalkProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind

    def test_file_only_or_empty_targets_keep_future_argument_and_authority_claims_false(self):
        proof = self.proof(trigger=False)
        result = self.namespace['trigger_walk_observe'](self.namespace['trigger_observe'](proof))['trigger_walk_observation']
        self.assertEqual(result['targets'], []); self.assertFalse(result['conditional_walk_forecast_constructed'])
        for name in self.namespace['TRIGGER_WALK_AUTHORITIES']: self.assertIs(result[name], False)

    def test_missing_raw_extra_lookup_receipt_refuses_even_with_stale_positive_walk(self):
        proof = self.proof(trigger=False); del proof['effects']['ordinary_condition_name_lookups']
        proof['trigger_walk_observation'] = {'conditional_walk_forecast_constructed': True}
        with self.assertRaises(KeyError): self.namespace['trigger_walk_observe'](self.namespace['trigger_observe'](proof))

    def test_every_typed_extra_receipt_field_is_rebuilt(self):
        for field, value in (('samples', True), ('rows_sha256', 'f' * 64), ('installation_authorized', True)):
            proof = self.proof(trigger=False); proof['effects']['ordinary_condition_name_lookups'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'extra lookups'):
                self.namespace['trigger_walk_observe'](self.namespace['trigger_observe'](proof))


class TriggerWalkPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_real_private_snapshot_success_binds_all_fifteen_original_byte_hashes(self):
        proof = self.proof(trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        result = self.run_guard(); observed = json.loads(result.stdout)
        self.assertEqual(len(sources.RECEIPTS), 18)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.path.read_bytes(), data)

    def test_real_private_missing_raw_extra_lookup_refuses_no_json_and_preserves_input(self):
        proof = self.proof(trigger=False); del proof['effects']['ordinary_condition_name_lookups']
        proof['trigger_walk_observation'] = {'conditional_walk_forecast_constructed': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('ordinary_condition_name_lookups', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)


class TriggerWalkPipelineTests(unittest.TestCase):
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    @classmethod
    def setUpClass(cls):
        # Two explicit additions to the finite delivery, not native/vendor
        # behavior: a same-name installed Provide and an absent condition name.
        ordinary = subprocess.run
        def delivery(command, *args, **options):
            if command[0] == 'cc' and isinstance(options.get('input'), str):
                material = options['input']
                old_name = 'incoming(h)?"userland":"virtual-capability"'
                old_condition = 'setting("condition_ordinary")?"userland":"/usr/lib"'
                assert material.count(old_name) == material.count(old_condition) == 1
                options['input'] = material.replace(old_name,
                    '(incoming(h)||setting("walk_installed_provider"))?"userland":"virtual-capability"').replace(
                    old_condition, 'setting("condition_ordinary")?(setting("walk_absent_name")?"absent":"userland"):"/usr/lib"')
            return ordinary(command, *args, **options)
        with patch.object(subprocess, 'run', side_effect=delivery):
            matches.HeaderMatchPipelineTests.setUpClass.__func__(cls)

    def test_fresh_current_positive_retains_conditional_calls_marks_and_fifteen_hashes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, walk_installed_provider=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_walk_observation']; case = receipt['targets'][0]['hypothetical_scenarios'][0]
        self.assertEqual((case['sample'], case['phase'], case['hypothetical_count_correction']), ('before', 'in', -1))
        self.assertEqual(case['final_marked_slots'], [0]); self.assertEqual(len(case['conditional_call_attempts']), 1)
        call = case['conditional_call_attempts'][0]
        self.assertEqual((call['source_owner']['kind'], call['source_owner']['instance'], call['conditional_arg1'], call['conditional_arg2']), ('installed', 1, 0, 1))
        self.assertTrue(all(not row['conditional_call_attempts'] for row in receipt['targets'][0]['hypothetical_scenarios'] if row['phase'] != 'in'))
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        authority_namespace = {'__name__': 'walk_authority_fixture'}
        exec(compile(triggers.emitted(), '<current-walk-authorities>', 'exec'), authority_namespace)
        for name in authority_namespace['TRIGGER_WALK_AUTHORITIES']: self.assertIs(receipt[name], False)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer); self.assertIn('run 1', self.native_calls())
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'native_test_seen': True, 'ordinary_cleanup_verified': True, 'explicit_installed_provide_delivery_model': True}

    def test_missing_condition_name_is_actually_looked_up_before_and_after_test(self):
        self.prepare(condition_ordinary=True, walk_absent_name=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_walk_observation']; extra = receipt['extra_current_name_lookups']
        self.assertEqual(extra['names'], 1); self.assertEqual(extra['new_rpm_api_calls'], 22)
        self.assertEqual(extra['rows'][0]['name'], 'absent')
        self.assertEqual(extra['rows'][0]['before'], {'count_start': 0, 'count_end': 0, 'order': [], 'iterator_present': False})
        self.assertEqual(extra['rows'][0]['before'], extra['rows'][0]['after'])
        self.assertEqual(receipt['hypothetical_scenarios'], 16)
        self.assertTrue(all(row['conditional_call_attempts'] == [] for row in receipt['targets'][0]['hypothetical_scenarios']))
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer); self.assertIn('run 1', self.native_calls())
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'native_test_seen': True, 'ordinary_cleanup_verified': True, 'explicit_absent_name_delivery_model': True}

    def test_fresh_test_replays_current_installed_sources_only_without_consuming_future_arg2_unknown(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_walk_observation']; self.assertEqual(receipt['target_headers'], 1)
        self.assertEqual(receipt['hypothetical_scenarios'], 16)
        self.assertTrue(all(case['conditional_call_attempts'] == [] for case in receipt['targets'][0]['hypothetical_scenarios']))
        self.assertEqual(receipt['targets'][0]['hypothetical_scenarios'][0]['lookups'][0]['source_visits'][0]['source_owner']['kind'], 'installed')
        old = proof['trigger_argument_observation']['pairs'][1]['hypothetical_phases'][0]['hypothetical_corrections'][0]['immediate_if_unmarked']
        self.assertIsNone(old['conditional_arg2']); self.assertTrue(old['fresh_iterator_count_required'])
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'native_test_seen': True, 'ordinary_cleanup_verified': True, 'finite_model_not_vendor_runtime': True}

    def test_complete_walk_bound_refuses_after_current_test_no_json_and_preserves_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        program = triggers.emitted(); model = program.replace('TRIGGER_WALK_WORK = 131072', 'TRIGGER_WALK_WORK = 0').replace(
            'C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        self.assertNotEqual(model, program); path = self.root / 'walk-bound-model.py'; path.write_text(model)
        import shlex
        result = self.shell('s4_update_trigger_inputs_program() { cat ' + shlex.quote(str(path)) + '; }; s4_check_update_effects', expected=75)
        self.assertIn('trigger walk complete repeated-row work exceeds its bound', result.stderr)
        self.assertEqual(result.stdout, ''); self.assertIn('run 1', self.native_calls())
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'native_test_seen': True, 'ordinary_cleanup_verified': True, 'explicit_bound_delivery_model': True}


if __name__ == '__main__': unittest.main()

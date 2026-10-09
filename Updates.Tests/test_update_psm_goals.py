import copy
import ctypes as C
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class PsmGoalForecastTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def inputs(self, empty=False, linked=True):
        owners = [{'instance': i, 'name': name, 'nevra': name + '-0-1.x86_64',
                   'header_bytes': 24, 'header_sha256': str(i) * 64}
                  for i, name in enumerate(('userland', 'other', 'gpg-pubkey'), 1)]
        baseline = {'headers': len(owners), 'sha256': hashlib.sha256(json.dumps(
            [(row['instance'], row['header_sha256']) for row in owners], separators=(',', ':')).encode()).hexdigest()}
        incoming = [{'file': 'packages/' + str(i) + '.rpm', 'sha256': 'a' * 64, 'bytes': 15,
                     'name': 'userland', 'nevra': 'userland-1-1.x86_64',
                     'header_bytes': 24, 'header_sha256': 'b' * 64} for i in range(2)] if not empty else []
        removals = [owners[1], owners[0]] if not empty else []
        inventory, plan = self.namespace['transaction_element_plan'](
            {row['instance']: row for row in owners}, baseline, incoming, removals)
        _, names = self.namespace['trigger_count_plan']({row['instance']: row for row in owners}, baseline, incoming)
        values = [row['inventory_count'] for row in names]
        counts = self.namespace['trigger_count_receipt'](inventory, names, values, values)
        rows = [] if empty else [
            {'position': 0, 'owner': plan['incoming']['packages/0.rpm'], 'depends_on': None},
            {'position': 1, 'owner': plan['removals'][2], 'depends_on': 0 if linked else None},
            {'position': 2, 'owner': plan['removals'][1], 'depends_on': 0 if linked else None},
            {'position': 3, 'owner': plan['incoming']['packages/1.rpm'], 'depends_on': None}]
        elements = self.namespace['transaction_element_receipt'](inventory, plan, rows, copy.deepcopy(rows))
        return inventory, plan, counts, elements

    def forecast(self, **kw):
        return self.namespace['psm_goal_forecast'](*self.inputs(**kw))

    def case(self, goal, count=1, linked=False):
        return self.namespace['psm_goal_case'](goal, count, linked)

    def test_install_and_pretrans_add_one_with_zero_correction_even_when_unlinked(self):
        for goal in ('PKG_INSTALL', 'PKG_PRETRANS'):
            for count in (0, 1, 32768):
                for linked in (False, True):
                    with self.subTest(goal=goal, count=count, linked=linked):
                        row = self.case(goal, count, linked)
                        self.assertEqual((row['conditional_package_script_arg'], row['conditional_count_correction']), (count + 1, 0))
                        self.assertIsNone(row['conditional_update_increment'])

    def test_erase_retains_negative_one_at_zero_and_negative_correction(self):
        for count in (0, 1, 32768):
            row = self.case('PKG_ERASE', count, True)
            self.assertEqual((row['conditional_package_script_arg'], row['conditional_count_correction']), (count - 1, -1))
            self.assertIsNone(row['conditional_update_increment'])

    def test_verify_and_posttrans_add_only_existential_update_bit(self):
        for goal in ('PKG_VERIFY', 'PKG_POSTTRANS'):
            for count in (0, 1, 32768):
                for linked in (False, True):
                    row = self.case(goal, count, linked)
                    self.assertEqual((row['conditional_package_script_arg'], row['conditional_count_correction']), (count + int(linked), 0))
                    self.assertEqual(row['conditional_update_increment'], int(linked))

    def test_unsupported_source_restore_trigger_goal_and_typed_operands_refuse(self):
        for goal, count, linked in (('PKG_RESTORE', 1, False), ('PKG_TRANSFILETRIGGERIN', 1, False),
            ('PKG_NONE', 1, False), (1, 1, False), (True, 1, False), ('PKG_ERASE', True, False),
            ('PKG_INSTALL', -1, False), ('PKG_INSTALL', 32769, False), ('PKG_VERIFY', 1, 1)):
            with self.subTest(goal=goal, count=count, linked=linked), self.assertRaises(ValueError): self.case(goal, count, linked)

    def test_multiple_removed_links_are_one_increment_not_link_multiplicity(self):
        result = self.forecast(); row = result['rows'][0]
        self.assertEqual(row['linked_removed_positions'], [1, 2]); self.assertTrue(row['current_removed_link_present'])
        self.assertEqual([case['conditional_package_script_arg'] for case in row['conditional_binary_goals']], [2, 2, 0, 2, 2])

    def test_cross_name_removed_link_contributes_without_obsoletes_approval(self):
        inventory, plan, counts, elements = self.inputs()
        for sample in ('before', 'after'): elements[sample][2]['depends_on'] = None
        elements = self.namespace['transaction_element_receipt'](inventory, plan, elements['before'], elements['after'])
        result = self.namespace['psm_goal_forecast'](inventory, plan, counts, elements)
        self.assertEqual(result['rows'][0]['linked_removed_positions'], [1])
        self.assertNotEqual(result['rows'][0]['owner']['name'], result['rows'][1]['owner']['name'])
        self.assertEqual(result['rows'][0]['conditional_binary_goals'][3]['conditional_package_script_arg'], 2)
        self.assertFalse(result['removal_policy_satisfied'])

    def test_same_name_incoming_elements_keep_distinct_link_targets_and_snapshot_identity(self):
        rows = self.forecast()['rows'][:4]
        self.assertEqual((rows[0]['owner']['name'], rows[3]['owner']['name']), ('userland', 'userland'))
        self.assertNotEqual(rows[0]['owner']['file'], rows[3]['owner']['file'])
        self.assertEqual(rows[3]['linked_removed_positions'], [])
        self.assertEqual(rows[3]['conditional_binary_goals'][3]['conditional_package_script_arg'], 1)

    def test_current_count_is_not_adjusted_by_incoming_or_removed_membership(self):
        result = self.forecast()
        self.assertEqual([row['current_installed_name_count'] for row in result['rows']], [1] * 8)
        self.assertEqual(result['hypothetical_goal_cases'], 40)

    def test_unlinked_elements_withhold_update_increment_for_verify_and_posttrans(self):
        for row in self.forecast(linked=False)['rows']:
            self.assertFalse(row['current_removed_link_present']); self.assertEqual(row['linked_removed_positions'], [])
            self.assertEqual([case['conditional_update_increment'] for case in row['conditional_binary_goals'][-2:]], [0, 0])

    def test_complete_before_after_matrix_digests_and_receipt_bindings_match_exact_bytes(self):
        args = self.inputs(); result = self.namespace['psm_goal_forecast'](*args)
        data = json.dumps(result['rows'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['rows_bytes'], result['rows_sha256']), (len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual([row['sample'] for row in result['rows']], ['before'] * 4 + ['after'] * 4)
        for value, name in ((args[2], 'current_counts_receipt_sha256'), (args[3], 'current_elements_receipt_sha256')):
            data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
            self.assertEqual(result[name], hashlib.sha256(data).hexdigest())

    def test_entire_later_row_is_admitted_before_any_forecast(self):
        for edit in (lambda e: e['after'][-1].update(position=True),
                     lambda e: e['after'][-1]['owner'].update(header_sha256='e' * 64),
                     lambda e: e['after'][-1].update(depends_on=0)):
            args = list(self.inputs()); edit(args[3])
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.namespace['psm_goal_forecast'](*args)

    def test_boolean_counts_corrupted_commitments_and_positive_authority_refuse(self):
        for edit in (lambda c: c['rows'][0].update(native_before=True), lambda c: c.update(rows_sha256='f' * 64),
                     lambda c: c.update(installation_authorized=True), lambda c: c['rows'].pop()):
            args = list(self.inputs()); edit(args[2])
            with self.subTest(edit=edit), self.assertRaisesRegex(ValueError, 'current count/element'): self.namespace['psm_goal_forecast'](*args)

    def test_partial_inventory_plan_and_stale_element_receipt_refuse(self):
        for edit in (lambda args: args[0]['entries'].pop(), lambda args: args[1]['removal_order'].pop(),
                     lambda args: args[3].update(dependency_links=[]), lambda args: args[3].update(elements=True)):
            args = list(self.inputs()); edit(args)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.namespace['psm_goal_forecast'](*args)

    def test_case_and_incremental_serialization_bounds_refuse_complete_matrix(self):
        with patch.dict(self.namespace, PSM_GOAL_CASES=39), self.assertRaisesRegex(ValueError, 'case count'): self.forecast()
        with patch.dict(self.namespace, PSM_GOAL_BYTES=100), self.assertRaisesRegex(ValueError, 'serialization'): self.forecast()

    def test_empty_transaction_with_checked_inventory_has_no_positive_forecast_or_new_calls(self):
        result = self.forecast(empty=True)
        self.assertEqual((result['hypothetical_goal_cases'], result['rows_bytes'], result['new_rpm_api_calls']), (0, 2, 0))
        self.assertEqual(result['rows'], []); self.assertFalse(result['conditional_goals_forecast'])

    def test_all_authorities_false_and_fresh_runtime_binary_count_link_prerequisites_remain(self):
        result = self.forecast()
        for name in self.namespace['PSM_GOAL_AUTHORITIES']: self.assertIs(result[name], False)
        self.assertTrue(result['fresh_runtime_count_and_links_required']); self.assertTrue(result['fresh_runtime_binary_branch_required'])
        self.assertEqual(result['new_rpm_api_calls'], 0); self.assertIn('UNSELECTED', result['scope'])


class PsmGoalOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
        temporary = tempfile.TemporaryDirectory(prefix='s4-psm-goal-oracle-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.root = Path(temporary.name)
        cls.library = cls.root / 'oracle.so'
        subprocess.run(['cc', '-shared', '-fPIC', str(Path(__file__).with_name('rpm_psm_goals_model.c')),
                        '-o', str(cls.library)], capture_output=True, text=True, check=True)
        cls.lib = C.CDLL(str(cls.library)); cls.oracle = cls.lib.model_psm_goal
        cls.oracle.restype = C.c_int
        cls.oracle.argtypes = (C.c_int, C.c_int, C.c_int, C.POINTER(C.c_int), C.c_int, C.c_int,
                              C.POINTER(C.c_int), C.POINTER(C.c_int))

    def call(self, goal, count, target, links, fault=0):
        array = (C.c_int * len(links))(*links); argument, correction = C.c_int(), C.c_int()
        self.assertEqual(self.oracle(goal, count, target, array, len(links), fault,
                                    C.byref(argument), C.byref(correction)), 0)
        return argument.value, correction.value

    def test_finite_c_formula_oracle_matches_five_goals_counts_and_existential_edges(self):
        pairs = 0
        for count in (0, 1, 2, 7, 32768):
            for target, links in ((0, []), (0, [-1]), (0, [0]), (1, [0, 1]), (0, [0, 0, -1])):
                for index, goal in enumerate(self.namespace['PSM_GOALS']):
                    expected = self.namespace['psm_goal_case'](goal, count, target in links)
                    self.assertEqual(self.call(index, count, target, links),
                        (expected['conditional_package_script_arg'], expected['conditional_count_correction']))
                    pairs += 1
        self.record = {'finite_model_comparisons': pairs, 'vendor_pkgGoal_abi_used': False, 'scripts_executed': False}

    def test_unshipped_sum_links_sensitivity_differs_only_for_multiple_update_edges(self):
        self.assertEqual(self.call(3, 1, 0, [0, 0]), (2, 0))
        self.assertEqual(self.call(3, 1, 0, [0, 0], fault=1), (3, 0))
        self.assertEqual(self.call(0, 1, 0, [0, 0], fault=1), (2, 0))
        self.record = {'unshipped_model_fault': 'sum matching removed links instead of existential break',
                       'intact_model_verify': [2, 0], 'modified_model_verify': [3, 0], 'product_failure_claim': False}


class PsmGoalPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_success_binds_seventeen_original_byte_hashes_without_input_change(self):
        proof = self.proof(trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        observed = json.loads(self.run_guard().stdout); self.assertEqual(len(sources.RECEIPTS), 17)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.path.read_bytes(), data); self.assertFalse(observed['psm_goal_observation']['installation_authorized'])

    def test_stale_positive_forecast_cannot_replace_missing_current_elements(self):
        proof = self.proof(trigger=False); del proof['effects']['ordered_transaction_elements']
        proof['psm_goal_observation'] = {'conditional_goals_forecast': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('ordered_transaction_elements', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)

    def test_boolean_current_name_count_is_refused_without_json_or_input_change(self):
        proof = self.proof(trigger=False); proof['effects']['installed_name_counts']['rows'][0]['native_before'] = True
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('raw native receipt differs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)


class PsmGoalPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_forecast_retains_goal_count_link_and_seventeen_hash_bindings(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['psm_goal_observation']; self.assertEqual(receipt['hypothetical_goal_cases'], 20)
        self.assertEqual([row['conditional_package_script_arg'] for row in receipt['rows'][0]['conditional_binary_goals']], [2, 2, 0, 2, 2])
        self.assertEqual(receipt['rows'][0]['linked_removed_positions'], [1])
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        for name in self.namespace_authorities(): self.assertIs(receipt[name], False)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'native_test_seen': True, 'finite_model_not_vendor_psm': True}

    def namespace_authorities(self):
        return ['headers_authenticated', 'native_library_identity_authenticated', 'database_authenticated',
                'trigger_eligibility_complete', 'installation_authorized', 'server_ready', 'transaction_goal_selected',
                'runtime_psm_created', 'binary_psm_branch_observed', 'runtime_count_correction_observed', 'package_scripts_executed']

    def test_goal_case_bound_model_refuses_after_current_test_no_json_pointer_and_cleanup(self):
        self.prepare(userland_removal=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        original = triggers.emitted()
        model = original.replace('PSM_GOAL_CASES = 65536', 'PSM_GOAL_CASES = 0').replace(
            'C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        self.assertNotEqual(model, original); path = self.root / 'psm-goal-bound-model.py'; path.write_text(model)
        result = self.shell('s4_update_trigger_inputs_program() { cat ' + shlex.quote(str(path)) + '; }; s4_check_update_effects', expected=75)
        self.assertIn('PSM goal hypothetical case count exceeds its bound', result.stderr)
        self.assertEqual(result.stdout, ''); self.assertIn('run 1', self.native_calls())
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'native_test_seen': True, 'explicit_bound_delivery_model': True}

    def test_empty_batch_with_current_database_observation_claims_no_psm_or_package_test(self):
        self.prepare(empty=True); proof = json.loads(self.shell().stdout); receipt = proof['psm_goal_observation']
        self.assertEqual((receipt['hypothetical_goal_cases'], receipt['rows'], receipt['new_rpm_api_calls']), (0, [], 0))
        self.assertFalse(receipt['conditional_goals_forecast']); self.assertFalse(proof['rpm_test_performed'])
        self.assertFalse(receipt['runtime_psm_created']); self.assertFalse(receipt['binary_psm_branch_observed'])

    def test_package_script_arguments_do_not_fill_immediate_trigger_arg2_or_select_routes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        proof = json.loads(self.shell().stdout)
        for pair in proof['trigger_argument_observation']['pairs']:
            for phase in pair['hypothetical_phases']:
                for row in phase['hypothetical_corrections']:
                    self.assertIsNone(row['immediate_if_unmarked']['conditional_arg2'])
                    if row['immediate_if_unmarked']['would_reach_script_call']:
                        self.assertTrue(row['immediate_if_unmarked']['fresh_iterator_count_required'])
        self.assertFalse(proof['psm_goal_observation']['transaction_goal_selected'])
        self.assertFalse(proof['trigger_argument_observation']['script_arguments_selected'])


if __name__ == '__main__': unittest.main()

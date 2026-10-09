import copy
import ctypes as C
import hashlib
import json
import os
import shlex
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_transaction_elements as elements
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class PsmInputReceiptTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)
    plan = elements.TransactionElementPlanTests.plan
    rows = elements.TransactionElementPlanTests.rows

    def inputs(self, flags=(0, 0)):
        inventory, plan = self.plan(); rows = self.rows(plan)
        receipt = self.namespace['transaction_element_receipt'](inventory, plan, rows, copy.deepcopy(rows))
        before = [{'element': row, 'is_source': flag} for row, flag in zip(rows, flags)]
        return inventory, plan, receipt, before, copy.deepcopy(before)

    def receipt(self, edit=None):
        values = self.inputs()
        if edit: edit(values[-1])
        return self.namespace['psm_input_receipt'](*values)

    def test_complete_flags_bind_full_element_owners_links_and_baseline(self):
        result = self.receipt(); data = json.dumps(result['before'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['elements'], result['new_rpm_api_calls'], result['new_source_getter_calls']), (2, 30, 10))
        self.assertEqual((result['rows_bytes'], result['rows_sha256']), (len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual(result['before'][1]['element']['depends_on'], 0)
        for name in self.namespace['PSM_INPUT_AUTHORITIES']: self.assertIs(result[name], False)

    def test_source_one_is_captured_without_inventing_a_binary_forecast(self):
        result = self.namespace['psm_input_receipt'](*self.inputs((0, 1)))
        self.assertEqual(result['before'][1]['is_source'], 1)
        self.assertNotIn('current_binary_elements_observed', result)
        self.assertFalse(result['binary_psm_branch_observed'])

    def test_empty_rows_keep_actual_controls_and_withhold_positive_observation(self):
        inventory, plan = self.plan(); plan.update(incoming={}, removals={}, removal_order=[])
        receipt = self.namespace['transaction_element_receipt'](inventory, plan, [], [])
        result = self.namespace['psm_input_receipt'](inventory, plan, receipt, [], [])
        self.assertFalse(result['current_source_flags_observed'])
        self.assertEqual((result['new_rpm_api_calls'], result['new_source_getter_calls']), (14, 2))

    def test_boolean_negative_out_of_range_and_missing_flags_refuse(self):
        for flag in (True, False, -1, 2, '0', None):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'source row'):
                self.receipt(lambda rows: rows[1].update(is_source=flag))
        with self.assertRaises(ValueError): self.receipt(lambda rows: rows[1].pop('is_source'))

    def test_missing_later_duplicate_extra_and_wrong_owner_rows_refuse(self):
        for edit in (lambda rows: rows.pop(), lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
                     lambda rows: rows[1].update(extra=False), lambda rows: rows[1]['element']['owner'].update(instance=True)):
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.receipt(edit)

    def test_post_test_source_change_refuses_the_complete_receipt(self):
        with self.assertRaisesRegex(ValueError, 'across TEST'):
            self.receipt(lambda rows: rows[1].update(is_source=1))

    def test_stale_element_digest_or_boolean_accounting_cannot_bind_source_rows(self):
        for field, value in (('rows_sha256', 'f' * 64), ('new_rpm_api_calls', True)):
            values = self.inputs(); values[2][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'element receipt'):
                self.namespace['psm_input_receipt'](*values)

    def test_complete_serialization_bound_withholds_partial_receipt(self):
        with patch.dict(self.namespace, PSM_INPUT_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization'):
            self.receipt()


class PsmInputNativeTests(unittest.TestCase):
    setUpClass = classmethod(elements.TransactionElementNativeTests.setUpClass.__func__)
    setUp = elements.TransactionElementNativeTests.setUp
    plan = elements.TransactionElementPlanTests.plan

    def sample(self):
        api = self.namespace['psm_input_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        return self.namespace['psm_input_sample'](api, self.transaction, database, handles, self.element_plan, rows)

    def test_borrowed_getter_has_full_two_pass_binary_readbacks_without_new_ownership(self):
        before = self.sample(); after = self.sample()
        self.assertEqual(before, after); self.assertEqual([row['is_source'] for row in before], [0, 0])
        self.record = {'before': before, 'after': after, 'new_ownership_transfers': 0, 'package_test_performed': False}

    def test_valid_source_getter_one_is_observed_and_not_relabeled_binary(self):
        with patch.dict(os.environ, element_source_removed='1'): rows = self.sample()
        self.assertEqual([row['is_source'] for row in rows], [0, 1])
        self.record = {'rows': rows, 'source_flag_is_native_declaration_not_authentication': True, 'package_test_performed': False}

    def test_exact_complete_two_sample_call_accounting_excludes_inherited_work(self):
        api = self.namespace['psm_input_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        calls = {}
        for name, actual in tuple(api.items()):
            def recorded(*args, name=name, actual=actual):
                calls[name] = calls.get(name, 0) + 1; return actual(*args)
            api[name] = recorded
        before = self.namespace['psm_input_sample'](api, self.transaction, database, handles, self.element_plan, rows)
        after = self.namespace['psm_input_sample'](api, self.transaction, database, handles, self.element_plan, rows)
        element_receipt = self.namespace['transaction_element_receipt'](self.inventory, self.element_plan, rows, rows)
        result = self.namespace['psm_input_receipt'](self.inventory, self.element_plan, element_receipt, before, after)
        self.assertEqual(sum(calls.values()), result['new_rpm_api_calls'])
        self.assertEqual(calls['rpmteIsSource'], result['new_source_getter_calls'])
        self.assertEqual(calls, {'rpmtsNElements': 4, 'rpmtsGetRdb': 4, 'rpmtsGetDBMode': 4,
                                'rpmtsElement': 8, 'rpmteIsSource': 10})
        self.record = {'actual_calls': calls, 'receipt': result, 'package_test_performed': False}

    def test_missing_symbol_or_non_lp64_refuses_before_source_getters(self):
        class Hidden:
            def __getattr__(inner, name):
                if name == 'rpmteIsSource': raise AttributeError(name)
                return getattr(self.lib, name)
        with self.assertRaisesRegex(ValueError, 'symbol is missing'): self.namespace['psm_input_bind'](Hidden())
        with patch.object(self.namespace['platform'], 'machine', return_value='unsupported'), self.assertRaisesRegex(ValueError, 'ABI'):
            self.namespace['psm_input_bind'](self.lib)

    def test_bad_null_and_invalid_source_values_refuse(self):
        for flag, message in (('element_source_null_invalid', 'NULL getter'), ('element_source_invalid', 'source row')):
            with patch.dict(os.environ, {flag: '1'}), self.subTest(flag=flag), self.assertRaisesRegex(ValueError, message): self.sample()

    def test_foreign_duplicate_missing_ts_and_db_handles_refuse_before_getter(self):
        api = self.namespace['psm_input_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        api['rpmteIsSource'] = lambda handle: self.fail('getter before complete handle admission')
        for value in (None, True, self.transaction, database, handles[0]):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'borrowed handles'):
                self.namespace['psm_input_sample'](api, self.transaction, database, [handles[0], value], self.element_plan, rows)

    def test_full_second_source_pass_change_refuses(self):
        api = self.namespace['psm_input_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        calls = 0
        def changed(handle):
            nonlocal calls
            calls += 1
            return int(calls > 3)
        api['rpmteIsSource'] = changed
        with self.assertRaisesRegex(ValueError, 'readback changed'):
            self.namespace['psm_input_sample'](api, self.transaction, database, handles, self.element_plan, rows)

    def test_changed_context_order_and_boolean_context_refuse_before_getter(self):
        api = self.namespace['psm_input_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        for name, function in (('rpmtsGetDBMode', lambda ts: True), ('rpmtsElement', lambda ts, index: True),
                               ('rpmtsGetRdb', lambda ts: self.transaction), ('rpmtsNElements', lambda ts: True)):
            changed = {**api, name: function, 'rpmteIsSource': lambda handle: self.fail('getter before context')}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'context/order'):
                self.namespace['psm_input_sample'](changed, self.transaction, database, handles, self.element_plan, rows)


class PsmInputPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_binary_success_binds_eighteen_original_hashes_and_no_runtime_authority(self):
        proof = self.proof(trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        observed = json.loads(self.run_guard().stdout); self.assertEqual(len(sources.RECEIPTS), 19)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.path.read_bytes(), data)
        for flag in self.namespace['PSM_INPUT_AUTHORITIES']: self.assertIs(observed['psm_input_observation'][flag], False)

    def test_stale_positive_receipt_cannot_replace_missing_raw_source_observation(self):
        proof = self.proof(trigger=False); del proof['effects']['current_psm_inputs']
        proof['psm_input_observation'] = {'current_binary_elements_observed': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('current_psm_inputs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)

    def test_corrupted_source_receipt_accounting_or_authority_withholds_all_json(self):
        for field, value in (('new_rpm_api_calls', True), ('rows_sha256', 'f' * 64), ('binary_psm_branch_observed', True)):
            proof = self.proof(trigger=False); proof['effects']['current_psm_inputs'][field] = value
            data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
            with self.subTest(field=field):
                self.assertIn('raw source receipt differs', result.stderr); self.assertEqual(result.stdout, '')
                self.assertEqual(self.path.read_bytes(), data)


class PsmInputPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_requires_same_binary_source_rows_and_all_eighteen_hashes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['psm_input_observation']; self.assertTrue(receipt['current_binary_elements_observed'])
        self.assertEqual((receipt['elements'], receipt['new_rpm_api_calls']), (2, 30))
        self.assertEqual([row['is_source'] for row in receipt['before']], [0, 0])
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer); self.assertIn('run 1', self.native_calls())
        self.assertFalse(receipt['binary_psm_branch_observed']); self.assertFalse(receipt['runtime_binary_state_continuous'])
        self.record = {'proof': proof, 'native_test_seen': True, 'ordinary_cleanup_verified': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_stable_source_one_defers_after_test_and_preserves_pointer_cleanup(self):
        self.prepare(userland_removal=True, element_source_removed=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('CURRENT source transaction element defers', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'ordinary_cleanup_verified': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_post_test_source_change_withholds_complete_json_and_keeps_pointer(self):
        self.prepare(userland_removal=True, element_source_changed=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('source observations changed across TEST', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'ordinary_cleanup_verified': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_invalid_source_getter_refuses_before_test_no_json_pointer_preserved(self):
        self.prepare(userland_removal=True, element_source_invalid=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('PSM input source row', result.stderr); self.assertEqual(result.stdout, '')
        self.assertNotIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_empty_batch_has_real_controls_but_no_binary_forecast_or_package_test(self):
        self.prepare(empty=True); proof = json.loads(self.shell().stdout); receipt = proof['psm_input_observation']
        self.assertEqual((receipt['elements'], receipt['new_rpm_api_calls'], receipt['new_source_getter_calls']), (0, 14, 2))
        self.assertFalse(receipt['current_binary_elements_observed']); self.assertFalse(proof['rpm_test_performed'])
        self.assertFalse(proof['psm_goal_observation']['conditional_goals_forecast'])

    def test_interpreter_removal_bypasses_do_not_enable_or_borrow_psm_source_projection(self):
        source = triggers.emitted()
        self.assertIn('psm_inputs_projection = False', source)
        self.assertTrue(source.endswith('if trigger_execution:\n    raise SystemExit(trigger_main(psm_route_observe))\n'))
        self.assertEqual(source.count('def psm_input_sample('), 1)
        self.assertIn('psm_inputs_projection = True', effects_program())


def effects_program():
    return (triggers.effects.SOURCE.parent / 'Updates/diagnostics.sh.in').read_text()


if __name__ == '__main__': unittest.main()

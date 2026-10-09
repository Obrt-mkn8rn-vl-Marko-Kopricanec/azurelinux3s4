import copy
import ctypes as C
import hashlib
import json
import os
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_transaction_elements as elements
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class PsmFailureReceiptTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)
    plan = elements.TransactionElementPlanTests.plan
    rows = elements.TransactionElementPlanTests.rows

    def inputs(self, counts=(0, 0)):
        inventory, plan = self.plan(); rows = self.rows(plan)
        receipt = self.namespace['transaction_element_receipt'](inventory, plan, rows, copy.deepcopy(rows))
        before = [{'element': row, 'failure_count': count} for row, count in zip(rows, counts)]
        return inventory, plan, receipt, before, copy.deepcopy(before)

    def receipt(self, edit=None):
        values = self.inputs()
        if edit: edit(values[-1])
        return self.namespace['psm_failure_receipt'](*values)

    def test_complete_counts_bind_full_owners_links_baseline_and_serialized_rows(self):
        result = self.receipt(); data = json.dumps(result['before'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['elements'], result['new_rpm_api_calls'], result['new_failure_getter_calls']), (2, 30, 10))
        self.assertEqual((result['rows_bytes'], result['rows_sha256']), (len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual(result['before'][1]['element']['depends_on'], 0)
        self.assertEqual(result['before'][1]['element']['owner']['instance'], 1)

    def test_positive_and_maximum_signed_counts_are_observations_without_eligibility(self):
        result = self.namespace['psm_failure_receipt'](*self.inputs((1, 2**31 - 1)))
        self.assertEqual([row['failure_count'] for row in result['before']], [1, 2**31 - 1])
        self.assertNotIn('current_zero_failure_counts_observed', result)
        self.assertFalse(result['transaction_processing_eligible'])

    def test_all_thirty_five_authorities_are_false_including_authentication_and_continuity(self):
        result = self.receipt(); names = self.namespace['PSM_FAILURE_AUTHORITIES']
        self.assertEqual(len(names), 35); self.assertEqual(len(set(names)), 35)
        for name in names: self.assertIs(result[name], False)

    def test_empty_retains_real_controls_without_positive_count_or_package_test_fact(self):
        inventory, plan = self.plan(); plan.update(incoming={}, removals={}, removal_order=[])
        receipt = self.namespace['transaction_element_receipt'](inventory, plan, [], [])
        result = self.namespace['psm_failure_receipt'](inventory, plan, receipt, [], [])
        self.assertFalse(result['current_failure_counts_observed'])
        self.assertEqual((result['new_rpm_api_calls'], result['new_failure_getter_calls']), (14, 2))
        self.assertNotIn('rpm_test_performed', result)

    def test_boolean_negative_overflow_string_and_null_counts_refuse(self):
        for count in (True, False, -1, -2, 2**31, '0', None):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, 'signed count'):
                self.receipt(lambda rows: rows[1].update(failure_count=count))

    def test_missing_later_duplicate_extra_and_wrong_owner_rows_refuse(self):
        for edit in (lambda rows: rows.pop(), lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
                     lambda rows: rows[1].update(extra=False), lambda rows: rows[1].pop('failure_count'),
                     lambda rows: rows[1]['element']['owner'].update(instance=True)):
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.receipt(edit)

    def test_nonzero_later_change_refuses_entire_receipt_after_test(self):
        with self.assertRaisesRegex(ValueError, 'across TEST'):
            self.receipt(lambda rows: rows[1].update(failure_count=2))

    def test_stale_element_digest_boolean_accounting_and_links_cannot_bind_failure_rows(self):
        for field, value in (('rows_sha256', 'f' * 64), ('new_rpm_api_calls', True), ('dependency_links', [])):
            values = self.inputs(); values[2][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'element receipt'):
                self.namespace['psm_failure_receipt'](*values)

    def test_complete_serialization_bound_withholds_receipt(self):
        with patch.dict(self.namespace, PSM_FAILURE_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization'):
            self.receipt()


class PsmFailureNativeTests(unittest.TestCase):
    setUpClass = classmethod(elements.TransactionElementNativeTests.setUpClass.__func__)
    setUp = elements.TransactionElementNativeTests.setUp
    plan = elements.TransactionElementPlanTests.plan

    def context(self):
        api = self.namespace['psm_failure_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        return api, database, handles, rows

    def sample(self):
        api, database, handles, rows = self.context()
        return self.namespace['psm_failure_sample'](api, self.transaction, database, handles, self.element_plan, rows)

    def test_borrowed_two_pass_zero_counts_preserve_complete_elements_without_new_ownership(self):
        before = self.sample(); after = self.sample()
        self.assertEqual(before, after); self.assertEqual([row['failure_count'] for row in before], [0, 0])
        self.assertEqual(before[1]['element']['depends_on'], 0)
        self.record = {'before': before, 'after': after, 'new_ownership_transfers': 0, 'package_test_performed': False}

    def test_actual_positive_count_two_is_not_coerced_to_boolean_or_eligible(self):
        with patch.dict(os.environ, element_failure_removed='1'): rows = self.sample()
        self.assertEqual([row['failure_count'] for row in rows], [0, 2])
        self.record = {'rows': rows, 'failure_count_is_native_declaration_not_authentication': True, 'package_test_performed': False}

    def test_exact_two_sample_api_and_getter_accounting_excludes_inherited_work(self):
        api, database, handles, rows = self.context(); calls = {}
        for name, actual in tuple(api.items()):
            def recorded(*args, name=name, actual=actual):
                calls[name] = calls.get(name, 0) + 1; return actual(*args)
            api[name] = recorded
        before = self.namespace['psm_failure_sample'](api, self.transaction, database, handles, self.element_plan, rows)
        after = self.namespace['psm_failure_sample'](api, self.transaction, database, handles, self.element_plan, rows)
        ordered = self.namespace['transaction_element_receipt'](self.inventory, self.element_plan, rows, rows)
        receipt = self.namespace['psm_failure_receipt'](self.inventory, self.element_plan, ordered, before, after)
        self.assertEqual(sum(calls.values()), receipt['new_rpm_api_calls'])
        self.assertEqual(calls['rpmteFailed'], receipt['new_failure_getter_calls'])
        self.assertEqual(calls, {'rpmtsNElements': 4, 'rpmtsGetRdb': 4, 'rpmtsGetDBMode': 4,
                                'rpmtsElement': 8, 'rpmteFailed': 10})
        self.record = {'actual_calls': calls, 'receipt': receipt, 'package_test_performed': False}

    def test_explicit_signed_int_prototype_missing_symbol_and_non_lp64_admission(self):
        self.namespace['psm_failure_bind'](self.lib)
        self.assertIs(self.lib.rpmteFailed.restype, C.c_int)
        self.assertEqual(self.lib.rpmteFailed.argtypes, (C.c_void_p,))
        class Hidden:
            def __getattr__(inner, name):
                if name == 'rpmteFailed': raise AttributeError(name)
                return getattr(self.lib, name)
        with self.assertRaisesRegex(ValueError, 'symbol is missing'): self.namespace['psm_failure_bind'](Hidden())
        with patch.object(self.namespace['platform'], 'machine', return_value='unsupported'), self.assertRaisesRegex(ValueError, 'ABI'):
            self.namespace['psm_failure_bind'](self.lib)

    def test_native_null_minus_one_and_invalid_nonnull_counts_refuse(self):
        for flag, message in (('element_failure_null_invalid', 'NULL-minus-one'), ('element_failure_invalid', 'signed count')):
            with patch.dict(os.environ, {flag: '1'}), self.subTest(flag=flag), self.assertRaisesRegex(ValueError, message): self.sample()

    def test_typed_null_control_precedes_nonnull_failure_getters(self):
        api, database, handles, rows = self.context()
        for control in (True, False, 0, None, '-1'):
            def getter(handle, control=control):
                if handle is None: return control
                self.fail('nonnull getter before NULL control')
            with self.subTest(control=control), self.assertRaisesRegex(ValueError, 'NULL-minus-one'):
                self.namespace['psm_failure_sample']({**api, 'rpmteFailed': getter}, self.transaction, database, handles, self.element_plan, rows)

    def test_all_handle_bases_and_complete_membership_are_admitted_before_getters(self):
        api, database, handles, rows = self.context()
        api['rpmteFailed'] = lambda handle: self.fail('getter before complete handle admission')
        for values in ([1], [1, 1], [1, True], [1, None], [1, self.transaction], [1, database]):
            with self.subTest(handles=values), self.assertRaisesRegex(ValueError, 'borrowed handles'):
                self.namespace['psm_failure_sample'](api, self.transaction, database, values, self.element_plan, rows)

    def test_context_type_count_database_mode_and_order_refuse_before_getter(self):
        api, database, handles, rows = self.context()
        for name, function in (('rpmtsGetDBMode', lambda ts: True), ('rpmtsElement', lambda ts, index: True),
                               ('rpmtsGetRdb', lambda ts: self.transaction), ('rpmtsNElements', lambda ts: True)):
            changed = {**api, name: function, 'rpmteFailed': lambda handle: self.fail('getter before context')}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'context/order'):
                self.namespace['psm_failure_sample'](changed, self.transaction, database, handles, self.element_plan, rows)

    def test_full_later_readback_and_final_context_drift_refuse(self):
        api, database, handles, rows = self.context(); calls = 0
        def changed(handle):
            nonlocal calls
            if handle is None: return -1
            calls += 1; return int(calls > len(handles))
        with self.assertRaisesRegex(ValueError, 'readback changed'):
            self.namespace['psm_failure_sample']({**api, 'rpmteFailed': changed}, self.transaction, database, handles, self.element_plan, rows)
        original = api['rpmtsGetRdb']; visits = 0
        def drift(ts):
            nonlocal visits
            visits += 1; return original(ts) if visits == 1 else self.transaction
        with self.assertRaisesRegex(ValueError, 'context/order'):
            self.namespace['psm_failure_sample']({**api, 'rpmtsGetRdb': drift}, self.transaction, database, handles, self.element_plan, rows)


class PsmFailurePrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_zero_success_binds_twenty_original_hashes_and_false_authorities(self):
        proof = self.proof(trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        observed = json.loads(self.run_guard().stdout); self.assertEqual(len(sources.RECEIPTS), 21)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        for flag in self.namespace['PSM_FAILURE_AUTHORITIES']: self.assertIs(observed['psm_failure_observation'][flag], False)
        self.assertEqual(self.path.read_bytes(), data)

    def test_stale_positive_cannot_replace_missing_raw_failure_projection(self):
        proof = self.proof(trigger=False); del proof['effects']['current_psm_failures']
        proof['psm_failure_observation'] = {'current_zero_failure_counts_observed': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('current_psm_failures', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)

    def test_stable_positive_private_failure_refuses_complete_output_and_preserves_input(self):
        proof = self.proof(trigger=False); raw = proof['effects']['current_psm_failures']
        before = copy.deepcopy(raw['before']); before[0]['failure_count'] = 2
        owners = proof['effects']['installed_versions']; inventory, plan = self.namespace['transaction_element_plan'](
            {row['instance']: row for row in owners['entries']}, proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
        proof['effects']['current_psm_failures'] = self.namespace['psm_failure_receipt'](
            inventory, plan, proof['effects']['ordered_transaction_elements'], before, copy.deepcopy(before))
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('CURRENT failed transaction element defers', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)

    def test_corrupted_count_digest_and_authority_receipts_refuse_all_json(self):
        for field, value in (('new_rpm_api_calls', True), ('rows_sha256', 'f' * 64), ('transaction_processing_eligible', True)):
            proof = self.proof(trigger=False); proof['effects']['current_psm_failures'][field] = value
            data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
            with self.subTest(field=field):
                self.assertIn('raw receipt differs', result.stderr); self.assertEqual(result.stdout, '')
                self.assertEqual(self.path.read_bytes(), data)


class PsmFailurePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        matches.HeaderMatchPipelineTests.setUpClass.__func__(cls)
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_binds_zero_counts_twenty_hashes_pointer_and_ordinary_cleanup(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['psm_failure_observation']; self.assertTrue(receipt['current_zero_failure_counts_observed'])
        self.assertEqual((receipt['elements'], receipt['new_rpm_api_calls']), (2, 30))
        self.assertEqual([row['failure_count'] for row in receipt['before']], [0, 0])
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        for flag in self.namespace['PSM_FAILURE_AUTHORITIES']: self.assertIs(receipt[flag], False)
        self.assertTrue(receipt['fresh_runtime_failure_state_required']); self.assertIn('run 1', self.native_calls())
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'ordinary_cleanup_verified': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_stable_positive_native_count_two_defers_after_test_without_json(self):
        self.prepare(userland_removal=True, element_failure_removed=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('CURRENT failed transaction element defers', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'ordinary_cleanup_verified': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_post_test_failure_change_refuses_entire_json_and_preserves_pointer_cleanup(self):
        self.prepare(userland_removal=True, element_failure_changed=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('failure observations changed across TEST', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'ordinary_cleanup_verified': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_invalid_failure_getter_refuses_before_test_pointer_and_cleanup_preserved(self):
        self.prepare(userland_removal=True, element_failure_invalid=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('signed count', result.stderr); self.assertEqual(result.stdout, '')
        self.assertNotIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_empty_batch_keeps_actual_controls_without_positive_state_or_package_test(self):
        self.prepare(empty=True); proof = json.loads(self.shell().stdout); receipt = proof['psm_failure_observation']
        self.assertEqual((receipt['elements'], receipt['new_rpm_api_calls'], receipt['new_failure_getter_calls']), (0, 14, 2))
        self.assertFalse(receipt['current_zero_failure_counts_observed']); self.assertFalse(proof['rpm_test_performed'])
        self.assertFalse(proof['psm_route_observation']['conditional_routes_forecast'])

    def test_shipped_mandatory_hook_default_false_and_bypass_enablement_stay_distinct(self):
        source = triggers.emitted(); delivery = (triggers.effects.SOURCE.parent / 'Updates/diagnostics.sh.in').read_text()
        self.assertIn('psm_failures_projection = False', source)
        self.assertTrue(source.endswith('if trigger_execution:\n    raise SystemExit(trigger_main(psm_verification_observe))\n'))
        self.assertEqual(source.count('def psm_failure_sample('), 1)
        self.assertIn('psm_failures_projection = True', delivery)
        native = (triggers.effects.SOURCE.parent / 'Updates/rpm_test.py').read_text()
        self.assertEqual(native.count('if effects and psm_failures_projection:'), 2)


if __name__ == '__main__': unittest.main()

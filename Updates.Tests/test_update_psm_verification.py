import copy
import ctypes as C
import hashlib
import json
import os
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_psm_failures as failures
import test_update_transaction_elements as elements
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class PsmVerificationReceiptTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)
    plan = elements.TransactionElementPlanTests.plan
    rows = elements.TransactionElementPlanTests.rows

    def inputs(self):
        inventory, plan = self.plan(); rows = self.rows(plan)
        ordered = self.namespace['transaction_element_receipt'](inventory, plan, rows, copy.deepcopy(rows))
        before = [{'element': row, 'verification_mask': 1 << 30} for row in rows]
        after = [{'element': row, 'verification_mask': 3 if row['owner']['kind'] == 'incoming' else 1 << 30} for row in rows]
        return inventory, plan, ordered, before, after

    def receipt(self, edit=None):
        values = self.inputs()
        if edit: edit(values)
        return self.namespace['psm_verification_receipt'](*values)

    def test_expected_transition_binds_both_complete_arrays_owners_and_baseline(self):
        result = self.receipt(); data = json.dumps({'before': result['before'], 'after': result['after']}, sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual([row['verification_mask'] for row in result['before']], [1 << 30, 1 << 30])
        self.assertEqual([row['verification_mask'] for row in result['after']], [3, 1 << 30])
        self.assertEqual((result['rows_bytes'], result['rows_sha256']), (len(data), hashlib.sha256(data).hexdigest()))
        self.assertEqual((result['new_rpm_api_calls'], result['new_verification_getter_calls'], result['null_controls']), (48, 10, 8))
        self.assertEqual(result['after'][1]['element']['owner']['instance'], 1)
        self.assertEqual(result['after'][1]['element']['depends_on'], 0)

    def test_known_partial_zero_and_unattempted_masks_remain_declarations_before_policy(self):
        for value in (0, 1, 2, 3, 1 << 30):
            with self.subTest(mask=value):
                result = self.receipt(lambda values: values[-1][0].update(verification_mask=value))
                self.assertEqual(result['after'][0]['verification_mask'], value)
                self.assertNotIn('current_incoming_digest_and_signature_masks_observed', result)

    def test_boolean_negative_unknown_mixed_marker_and_overflow_masks_refuse(self):
        for value in (True, False, -1, 4, 7, (1 << 30) | 3, 1 << 31, '3', None):
            with self.subTest(mask=value), self.assertRaisesRegex(ValueError, 'supported mask'):
                self.receipt(lambda values: values[-1][0].update(verification_mask=value))

    def test_missing_duplicate_later_extra_and_wrong_owner_rows_refuse(self):
        for edit in (lambda rows: rows.pop(), lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
                     lambda rows: rows[1].update(extra=False), lambda rows: rows[1].pop('verification_mask'),
                     lambda rows: rows[1]['element']['owner'].update(instance=True)):
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.receipt(lambda values: edit(values[-1]))

    def test_stale_order_digest_boolean_accounting_and_dependency_receipt_refuse(self):
        for field, value in (('rows_sha256', 'f' * 64), ('new_rpm_api_calls', True), ('dependency_links', [])):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'element receipt'):
                self.receipt(lambda values: values[2].update({field: value}))

    def test_both_array_serialization_admission_precedes_complete_receipt(self):
        with patch.dict(self.namespace, PSM_VERIFICATION_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization'):
            self.receipt()

    def test_all_forty_authorities_false_and_policy_types_are_explicit(self):
        result = self.receipt(); names = self.namespace['PSM_VERIFICATION_AUTHORITIES']
        self.assertEqual(len(names), 40); self.assertEqual(len(set(names)), 40)
        for name in names: self.assertIs(result[name], False)
        self.assertEqual(result['verification_policy'], {'header_flags': 0, 'package_flags': 0, 'required_types': 3})

    def test_empty_keeps_controls_and_call_count_without_positive_masks_or_test_fact(self):
        inventory, plan = self.plan(); plan.update(incoming={}, removals={}, removal_order=[])
        ordered = self.namespace['transaction_element_receipt'](inventory, plan, [], [])
        result = self.namespace['psm_verification_receipt'](inventory, plan, ordered, [], [])
        self.assertEqual((result['new_rpm_api_calls'], result['new_verification_getter_calls'], result['null_controls']), (32, 2, 8))
        self.assertFalse(result['current_verification_masks_observed']); self.assertNotIn('rpm_test_performed', result)


class PsmVerificationNativeTests(unittest.TestCase):
    setUpClass = classmethod(elements.TransactionElementNativeTests.setUpClass.__func__)
    setUp = elements.TransactionElementNativeTests.setUp
    plan = elements.TransactionElementPlanTests.plan

    def context(self):
        api = self.namespace['psm_verification_bind'](self.lib)
        database, handles, rows = self.namespace['transaction_element_sample'](
            api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})
        return api, database, handles, rows

    def sample(self):
        api, database, handles, rows = self.context()
        return self.namespace['psm_verification_sample'](api, self.transaction, database, handles, self.element_plan, rows)

    def test_two_pass_unverified_before_and_declared_post_model_without_new_ownership(self):
        before = self.sample()
        with patch.dict(os.environ, verification_sample_post='1'): after = self.sample()
        self.assertEqual([row['verification_mask'] for row in before], [1 << 30, 1 << 30])
        self.assertEqual([row['verification_mask'] for row in after], [3, 1 << 30])
        self.record = {'before': before, 'after': after, 'explicit_post_state_delivery': True, 'package_test_performed': False, 'new_ownership_transfers': 0}

    def test_exact_api_mask_and_policy_accounting_excludes_inherited_work(self):
        api, database, handles, rows = self.context(); calls = {}
        for name, actual in tuple(api.items()):
            def recorded(*args, name=name, actual=actual):
                calls[name] = calls.get(name, 0) + 1; return actual(*args)
            api[name] = recorded
        before = self.namespace['psm_verification_sample'](api, self.transaction, database, handles, self.element_plan, rows)
        with patch.dict(os.environ, verification_sample_post='1'):
            after = self.namespace['psm_verification_sample'](api, self.transaction, database, handles, self.element_plan, rows)
        ordered = self.namespace['transaction_element_receipt'](self.inventory, self.element_plan, rows, rows)
        receipt = self.namespace['psm_verification_receipt'](self.inventory, self.element_plan, ordered, before, after)
        expected = {'rpmtsNElements': 4, 'rpmtsGetRdb': 4, 'rpmtsGetDBMode': 4, 'rpmtsElement': 8,
                    'rpmteVerified': 10, 'rpmtsVSFlags': 6, 'rpmtsVfyFlags': 6, 'rpmtsVfyLevel': 6}
        self.assertEqual(calls, expected); self.assertEqual(sum(calls.values()), receipt['new_rpm_api_calls'])
        self.assertEqual(calls['rpmteVerified'], receipt['new_verification_getter_calls'])
        self.record = {'actual_calls': calls, 'receipt': receipt, 'package_test_performed': False}

    def test_explicit_signed_mask_and_policy_prototypes_and_missing_symbol_refuse(self):
        self.namespace['psm_verification_bind'](self.lib)
        for name, result in (('rpmteVerified', C.c_int), ('rpmtsVSFlags', C.c_uint), ('rpmtsVfyFlags', C.c_uint), ('rpmtsVfyLevel', C.c_int)):
            with self.subTest(name=name):
                self.assertIs(getattr(self.lib, name).restype, result)
                self.assertEqual(getattr(self.lib, name).argtypes, (C.c_void_p,))
        class Hidden:
            def __getattr__(inner, name):
                if name == 'rpmteVerified': raise AttributeError(name)
                return getattr(self.lib, name)
        with self.assertRaisesRegex(ValueError, 'symbol is missing: rpmteVerified'):
            self.namespace['psm_verification_bind'](Hidden())

    def test_non_lp64_and_known_borrowed_handle_aliases_refuse_before_getters(self):
        with patch.object(C, 'sizeof', return_value=4), self.assertRaisesRegex(ValueError, 'trigger count ABI is unsupported'):
            self.namespace['psm_verification_bind'](self.lib)
        api, database, handles, rows = self.context(); visits = []
        api['rpmteVerified'] = lambda value: visits.append(value) or 0
        for value in (self.transaction, database, None, True, handles[0]):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'borrowed handles'):
                self.namespace['psm_verification_sample'](api, self.transaction, database, [handles[0], value], self.element_plan, rows)
        self.assertEqual(visits, [])

    def test_null_mask_and_policy_faults_refuse_without_positive_participation(self):
        for name in ('verification_null_invalid', 'verification_policy_null_invalid'):
            with self.subTest(name=name), patch.dict(os.environ, {name: '1'}), self.assertRaisesRegex(ValueError, 'NULL-zero'):
                self.sample()

    def test_each_relaxed_verification_policy_refuses_before_element_getters(self):
        for name in ('verification_header_relaxed', 'verification_package_relaxed', 'verification_level_relaxed'):
            with self.subTest(name=name), patch.dict(os.environ, {name: '1'}), self.assertRaisesRegex(ValueError, 'digest/signature policy'):
                self.sample()

    def test_invalid_native_and_boolean_mask_declarations_refuse(self):
        with patch.dict(os.environ, verification_invalid='1'), self.assertRaisesRegex(ValueError, 'supported mask'): self.sample()
        api, database, handles, rows = self.context()
        api['rpmteVerified'] = lambda value: 0 if value is None else True
        with self.assertRaisesRegex(ValueError, 'supported mask'):
            self.namespace['psm_verification_sample'](api, self.transaction, database, handles, self.element_plan, rows)

    def test_later_readback_and_policy_drift_refuse_complete_sample(self):
        api, database, handles, rows = self.context(); visits = 0
        def changed(value):
            nonlocal visits
            if value is None: return 0
            visits += 1; return 1 << 30 if visits <= len(handles) else 3
        with self.assertRaisesRegex(ValueError, 'readback changed'):
            self.namespace['psm_verification_sample']({**api, 'rpmteVerified': changed}, self.transaction, database, handles, self.element_plan, rows)
        visits = 0
        def policy(ts):
            nonlocal visits
            if ts is None: return 0
            visits += 1; return 3 if visits == 1 else 1
        with self.assertRaisesRegex(ValueError, 'digest/signature policy'):
            self.namespace['psm_verification_sample']({**api, 'rpmtsVfyLevel': policy}, self.transaction, database, handles, self.element_plan, rows)


class PsmVerificationPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_expected_transition_binds_twenty_one_hashes_no_authentication(self):
        proof = self.proof(trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        result = self.run_guard(); observed = json.loads(result.stdout); self.assertEqual(len(sources.RECEIPTS), 21)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        for name in self.namespace['PSM_VERIFICATION_AUTHORITIES']: self.assertIs(observed['psm_verification_observation'][name], False)
        self.assertEqual(self.path.read_bytes(), data)

    def test_missing_raw_verification_cannot_borrow_stale_positive_receipt(self):
        proof = self.proof(trigger=False); del proof['effects']['current_psm_verification']
        proof['psm_verification_observation'] = {'current_incoming_digest_and_signature_masks_observed': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('current_psm_verification', result.stderr); self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), data)

    def test_every_incoming_partial_none_unattempted_and_prior_verified_refuses_no_json(self):
        for stage, value in (('after', 0), ('after', 1), ('after', 2), ('after', 1 << 30), ('before', 3)):
            proof = self.proof(trigger=False); raw = proof['effects']['current_psm_verification']
            raw[stage][0]['verification_mask'] = value
            source = proof['effects']['installed_versions']; inventory, plan = self.namespace['transaction_element_plan'](
                {row['instance']: row for row in source['entries']}, proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
            proof['effects']['current_psm_verification'] = self.namespace['psm_verification_receipt'](
                inventory, plan, proof['effects']['ordered_transaction_elements'], raw['before'], raw['after'])
            data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
            with self.subTest(stage=stage, value=value):
                self.assertIn('prerequisite differs', result.stderr); self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), data)

    def test_corrupted_accounting_digest_policy_and_authority_refuse_no_json(self):
        for field, value in (('new_rpm_api_calls', True), ('rows_sha256', 'f' * 64), ('verification_policy', {'required_types': 1}), ('future_package_verification_complete', True)):
            proof = self.proof(trigger=False); proof['effects']['current_psm_verification'][field] = value
            data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
            with self.subTest(field=field):
                self.assertIn('raw receipt differs', result.stderr); self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), data)


class PsmVerificationPipelineTests(unittest.TestCase):
    setUpClass = classmethod(failures.PsmFailurePipelineTests.setUpClass.__func__)
    command = failures.PsmFailurePipelineTests.command
    configure = failures.PsmFailurePipelineTests.configure
    calls = failures.PsmFailurePipelineTests.calls
    setUp = failures.PsmFailurePipelineTests.setUp
    header = failures.PsmFailurePipelineTests.header
    prepare = failures.PsmFailurePipelineTests.prepare
    native_calls = failures.PsmFailurePipelineTests.native_calls
    shell = failures.PsmFailurePipelineTests.shell

    def test_fresh_test_records_expected_transition_complete_hashes_pointer_cleanup(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['psm_verification_observation']
        self.assertEqual([row['verification_mask'] for row in receipt['before']], [1 << 30, 1 << 30])
        self.assertEqual([row['verification_mask'] for row in receipt['after']], [3, 1 << 30])
        self.assertEqual((receipt['new_rpm_api_calls'], receipt['new_verification_getter_calls']), (48, 10))
        self.assertTrue(receipt['current_incoming_digest_and_signature_masks_observed']); self.assertTrue(receipt['fresh_runtime_verification_required'])
        self.assertEqual(len(sources.RECEIPTS), 21)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        for name in self.namespace['PSM_VERIFICATION_AUTHORITIES']: self.assertIs(receipt[name], False)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'ordinary_cleanup_verified': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(), 'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_digest_only_after_test_refuses_all_json_preserves_pointer_cleanup(self):
        self.prepare(userland_removal=True, verification_digest_only=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('post-TEST incoming digest/signature', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'ordinary_cleanup_verified': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(), 'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_signature_only_none_and_unattempted_refuse_after_qualified_test(self):
        for name in ('verification_signature_only', 'verification_none', 'verification_unattempted'):
            self.prepare(userland_removal=True, **{name: True}); pointer = (self.root / 'state/updates/current.json').read_bytes()
            result = self.shell(expected=75)
            with self.subTest(name=name):
                self.assertIn('post-TEST incoming digest/signature', result.stderr); self.assertEqual(result.stdout, '')
                self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_prior_verified_and_removed_verified_do_not_manufacture_fresh_authentication(self):
        for name in ('verification_prior', 'verification_removed'):
            self.prepare(userland_removal=True, **{name: True}); pointer = (self.root / 'state/updates/current.json').read_bytes()
            result = self.shell(expected=75)
            with self.subTest(name=name):
                self.assertIn('prerequisite differs', result.stderr); self.assertEqual(result.stdout, '')
                self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_relaxed_policy_and_unknown_mask_refuse_before_test_with_cleanup(self):
        for name in ('verification_header_relaxed', 'verification_package_relaxed', 'verification_level_relaxed', 'verification_invalid'):
            self.prepare(userland_removal=True, **{name: True}); pointer = (self.root / 'state/updates/current.json').read_bytes()
            result = self.shell(expected=75)
            with self.subTest(name=name):
                self.assertEqual(result.stdout, ''); self.assertNotIn('run 1', self.native_calls())
                self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_empty_has_real_controls_but_no_positive_incoming_verification_or_package_test(self):
        self.prepare(empty=True); proof = json.loads(self.shell().stdout); receipt = proof['psm_verification_observation']
        self.assertEqual((receipt['elements'], receipt['new_rpm_api_calls'], receipt['null_controls']), (0, 32, 8))
        self.assertFalse(receipt['current_verification_masks_observed']); self.assertFalse(receipt['current_incoming_digest_and_signature_masks_observed'])
        self.assertFalse(proof['rpm_test_performed']); self.record = {'proof': proof}

    def test_mandatory_hook_source_false_and_normal_enablement_are_distinct(self):
        source = triggers.emitted(); delivery = (triggers.effects.SOURCE.parent / 'Updates/diagnostics.sh.in').read_text()
        self.assertIn('psm_verification_projection = False', source)
        self.assertTrue(source.endswith('if trigger_execution:\n    raise SystemExit(trigger_main(psm_verification_observe))\n'))
        self.assertEqual(source.count('def psm_verification_sample('), 1); self.assertIn('psm_verification_projection = True', delivery)
        native = (triggers.effects.SOURCE.parent / 'Updates/rpm_test.py').read_text()
        self.assertEqual(native.count('if effects and psm_verification_projection:'), 2)


if __name__ == '__main__': unittest.main()

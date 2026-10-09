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

import test_update_effects as effects
import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class TransactionElementPlanTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def plan(self, removal=True):
        owner = {'instance': 1, 'name': 'userland', 'nevra': 'userland-0-1.x86_64',
                 'header_bytes': 24, 'header_sha256': 'a' * 64}
        baseline = {'headers': 1, 'sha256': hashlib.sha256(json.dumps([(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        incoming = {'file': 'packages/0.rpm', 'sha256': 'b' * 64, 'bytes': 15,
                    'name': 'userland', 'nevra': 'userland-1-1.x86_64', 'header_bytes': 24, 'header_sha256': 'c' * 64}
        return self.namespace['transaction_element_plan']({1: owner}, baseline, [incoming], [owner] if removal else [])

    def rows(self, plan):
        return [{'position': 0, 'owner': plan['incoming']['packages/0.rpm'], 'depends_on': None},
                {'position': 1, 'owner': plan['removals'][1], 'depends_on': 0}]

    def receipt(self, edit=None):
        inventory, plan = self.plan(); before = self.rows(plan); after = copy.deepcopy(before)
        if edit: edit(after)
        return self.namespace['transaction_element_receipt'](inventory, plan, before, after)

    def test_complete_order_and_same_captured_header_link_have_bounded_commitments(self):
        result = self.receipt(); encoded = json.dumps(result['before'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((result['elements'], result['new_rpm_api_calls']), (2, 72))
        self.assertEqual((result['rows_bytes'], result['rows_sha256']), (len(encoded), hashlib.sha256(encoded).hexdigest()))
        self.assertEqual(result['dependency_links'], [{'removed_position': 1, 'incoming_position': 0, 'same_package_name': True}])
        for name in self.namespace['TRANSACTION_ELEMENT_AUTHORITIES']: self.assertIs(result[name], False)

    def test_unlinked_removal_is_an_observation_and_does_not_invent_an_update_edge(self):
        inventory, plan = self.plan(); rows = self.rows(plan); rows[1]['depends_on'] = None
        result = self.namespace['transaction_element_receipt'](inventory, plan, rows, copy.deepcopy(rows))
        self.assertEqual(result['dependency_links'], []); self.assertFalse(result['current_dependency_links_observed'])

    def test_different_package_names_remain_explicit_without_obsoletes_policy_approval(self):
        inventory, plan = self.plan(); plan['incoming']['packages/0.rpm']['name'] = 'other'
        result = self.namespace['transaction_element_receipt'](inventory, plan, self.rows(plan), self.rows(plan))
        self.assertFalse(result['dependency_links'][0]['same_package_name']); self.assertFalse(result['removal_policy_satisfied'])

    def test_missing_duplicate_boolean_and_foreign_order_rows_refuse_complete_receipt(self):
        for edit in (lambda r: r.pop(), lambda r: r[1].update(position=True), lambda r: r[1].update(owner=r[0]['owner']),
                     lambda r: r[1]['owner'].update(instance=True), lambda r: r[1]['owner'].update(header_sha256='f' * 64)):
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.receipt(edit)

    def test_foreign_boolean_self_and_removed_dependency_positions_refuse(self):
        for dependency in (True, -1, 2, 1):
            with self.subTest(dependency=dependency), self.assertRaises(ValueError):
                self.receipt(lambda rows: rows[1].update(depends_on=dependency))

    def test_incoming_dependency_is_refused_and_later_link_change_is_not_atomic_success(self):
        with self.assertRaisesRegex(ValueError, 'incoming dependency'): self.receipt(lambda r: r[0].update(depends_on=0))
        with self.assertRaisesRegex(ValueError, 'across TEST'): self.receipt(lambda r: r[1].update(depends_on=None))

    def test_empty_transaction_has_real_two_sample_accounting_but_withholds_positive_elements(self):
        inventory, plan = self.plan(); plan.update(incoming={}, removals={}, removal_order=[])
        result = self.namespace['transaction_element_receipt'](inventory, plan, [], [])
        self.assertFalse(result['current_ordered_elements_observed']); self.assertEqual(result['new_rpm_api_calls'], 24)
        self.assertEqual(result['dependency_links'], [])

    def test_complete_plan_and_output_bounds_refuse_before_success(self):
        with patch.dict(self.namespace, TRANSACTION_ELEMENT_LIMIT=0), self.assertRaisesRegex(ValueError, 'plan exceeds'): self.plan()
        with patch.dict(self.namespace, TRANSACTION_ELEMENT_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization'): self.plan()
        inventory, plan = self.plan()
        with patch.dict(self.namespace, TRANSACTION_ELEMENT_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization'):
            self.namespace['transaction_element_receipt'](inventory, plan, self.rows(plan), self.rows(plan))

    def test_reordered_addition_is_kept_but_exact_removed_order_is_required(self):
        inventory, plan = self.plan(); rows = list(reversed(self.rows(plan)))
        for i, row in enumerate(rows): row['position'] = i
        rows[0]['depends_on'] = 1
        result = self.namespace['transaction_element_receipt'](inventory, plan, rows, copy.deepcopy(rows))
        self.assertEqual(result['dependency_links'][0]['incoming_position'], 1)


class TransactionElementNativeTests(unittest.TestCase):
    plan = TransactionElementPlanTests.plan

    @classmethod
    def setUpClass(cls):
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
        temporary = tempfile.TemporaryDirectory(prefix='s4-elements-api-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.root = Path(temporary.name); cls.library = cls.root / 'elements.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)], input=effects.LIBRARY,
                       text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library))
        cls.lib.rpmtsCreate.restype = C.c_void_p; cls.lib.rpmtsCreate.argtypes = ()
        cls.lib.rpmtsFree.restype = C.c_void_p; cls.lib.rpmtsFree.argtypes = (C.c_void_p,)
        cls.lib.rpmtsAddInstallElement.restype = C.c_int
        cls.lib.rpmtsAddInstallElement.argtypes = (C.c_void_p, C.c_void_p, C.c_char_p, C.c_int, C.c_void_p)
        cls.lib.rpmtsSetNotifyCallback.restype = C.c_int; cls.lib.rpmtsSetNotifyCallback.argtypes = (C.c_void_p, C.c_void_p, C.c_void_p)

    def setUp(self):
        self.environment = patch.dict(os.environ, S4_TEST_ROOT=str(self.root), userland_removal='1')
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.transaction = self.lib.rpmtsCreate()
        self.addCleanup(lambda: self.assertIsNone(self.lib.rpmtsFree(self.transaction)))
        self.assertEqual(self.lib.rpmtsAddInstallElement(self.transaction, None, b'/owned/0.rpm', 1, None), 0)
        self.assertEqual(self.lib.rpmtsSetNotifyCallback(self.transaction, None, None), 0)
        self.api = self.namespace['transaction_element_bind'](self.lib); self.inventory, self.element_plan = self.plan()

    def sample(self):
        return self.namespace['transaction_element_sample'](self.api, self.transaction, self.element_plan, {b'/owned/0.rpm': 'packages/0.rpm'})

    def test_actual_borrowed_two_pass_values_keep_handles_and_never_call_null_unsafe_getter(self):
        database, handles, rows = self.sample(); second, again, after = self.sample()
        self.assertEqual((database, handles, rows), (second, again, after)); self.assertEqual(handles, [1, 2])
        self.assertEqual(rows[1]['depends_on'], 0)
        self.record = {'before': rows, 'after': after, 'known_nonnull_handles': handles,
                       'no_new_ownership_transfer': True, 'package_test_performed': False,
                       'null_unsafe_getter_has_abort_control_in_c_delivery': True}

    def test_complete_two_sample_api_accounting_excludes_inherited_transaction_work(self):
        calls = {}
        for name, actual in tuple(self.api.items()):
            def recorded(*args, name=name, actual=actual):
                calls[name] = calls.get(name, 0) + 1
                return actual(*args)
            self.api[name] = recorded
        _, _, before = self.sample(); _, _, after = self.sample()
        receipt = self.namespace['transaction_element_receipt'](self.inventory, self.element_plan, before, after)
        self.assertEqual(sum(calls.values()), receipt['new_rpm_api_calls'])
        self.assertEqual((calls['rpmteDependsOn'], calls['rpmtsGetRdb'], calls['rpmtsGetDBMode']), (8, 4, 4))
        self.assertNotIn('rpmdbCountPackages', calls)

    def test_missing_symbol_and_non_lp64_refuse_before_element_getters(self):
        class Hidden:
            def __getattr__(inner, name):
                if name == 'rpmteDependsOn': raise AttributeError(name)
                return getattr(self.lib, name)
        with self.assertRaisesRegex(ValueError, 'symbol is missing'): self.namespace['transaction_element_bind'](Hidden())
        with patch.object(self.namespace['platform'], 'machine', return_value='unsupported'), self.assertRaisesRegex(ValueError, 'ABI'):
            self.namespace['transaction_element_bind'](self.lib)

    def test_bad_null_participation_refuses_before_any_nonnull_element_getters(self):
        self.api['rpmteDBInstance'] = lambda value: True
        self.api['rpmteDependsOn'] = lambda value: self.fail('getter before controls')
        with self.assertRaisesRegex(ValueError, 'NULL participation'): self.sample()

    def test_boundary_failure_precedes_nonnull_dependency_query(self):
        actual = self.api['rpmtsElement']; self.api['rpmtsElement'] = lambda ts, index: 99 if ts and index == -1 else actual(ts, index)
        self.api['rpmteDependsOn'] = lambda value: self.fail('getter before boundary controls')
        with self.assertRaisesRegex(ValueError, 'index boundary'): self.sample()

    def test_missing_duplicate_ts_and_database_handle_aliases_refuse_before_getter(self):
        actual = self.api['rpmtsElement']; database = self.api['rpmtsGetRdb'](self.transaction)
        for alias in (None, True, 1, self.transaction, database):
            self.api['rpmtsElement'] = lambda ts, index, alias=alias: alias if ts and index == 1 else actual(ts, index)
            self.api['rpmteDependsOn'] = lambda value: self.fail('getter before full handle admission')
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, 'borrowed handle'): self.sample()

    def test_foreign_removed_self_and_incoming_links_refuse_without_dereferencing_foreign_handle(self):
        for flag in ('element_foreign_dependency', 'element_removed_dependency', 'element_incoming_dependency'):
            with patch.dict(os.environ, {flag: '1'}), self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'dependency'): self.sample()
        self.record = {'foreign_links_refused': True, 'foreign_handles_never_getters_or_freed': True,
                       'package_test_performed': False, 'no_new_ownership_transfer': True}

    def test_changed_full_second_readback_and_terminal_order_refuse(self):
        actual = self.api['rpmteDependsOn']; calls = 0
        def changed(value):
            nonlocal calls
            calls += 1
            return None if calls > 2 else actual(value)
        self.api['rpmteDependsOn'] = changed
        with self.assertRaisesRegex(ValueError, 'readback'): self.sample()
        self.api = self.namespace['transaction_element_bind'](self.lib); original = self.api['rpmtsElement']; visits = 0
        def order(ts, index):
            nonlocal visits
            if ts and index == 0:
                visits += 1
                if visits > 1: return 2
            return original(ts, index)
        self.api['rpmtsElement'] = order
        with self.assertRaisesRegex(ValueError, 'readback'): self.sample()

    def test_wrong_snapshot_identity_instance_or_readonly_context_refuses(self):
        for name, replacement in (('rpmteKey', lambda value: b'/foreign.rpm'), ('rpmteN', lambda value: b'foreign'),
                                  ('rpmteDBInstance', lambda value: 0 if value is None else 999),
                                  ('rpmtsGetDBMode', lambda value: 1)):
            self.api = self.namespace['transaction_element_bind'](self.lib); self.api[name] = replacement
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'identity|context'): self.sample()


class TransactionElementPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_success_binds_all_sixteen_original_byte_receipts(self):
        proof = self.proof(trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        observed = json.loads(self.run_guard().stdout); self.assertEqual(len(sources.RECEIPTS), 18)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.path.read_bytes(), data)

    def test_missing_raw_receipt_cannot_borrow_stale_positive_and_emits_no_json(self):
        proof = self.proof(trigger=False); del proof['effects']['ordered_transaction_elements']
        proof['transaction_element_observation'] = {'current_ordered_elements_observed': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('ordered_transaction_elements', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), data)

    def test_boolean_count_digest_and_authority_corruption_refuse_complete_private_output(self):
        for field, value in (('elements', True), ('rows_sha256', 'f' * 64), ('installation_authorized', True)):
            proof = self.proof(trigger=False); proof['effects']['ordered_transaction_elements'][field] = value
            data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
            with self.subTest(field=field):
                self.assertIn('raw receipt differs', result.stderr); self.assertEqual(result.stdout, '')
                self.assertEqual(self.path.read_bytes(), data)


class TransactionElementPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_binds_complete_order_removal_link_and_all_sixteen_hashes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['transaction_element_observation']; self.assertEqual(receipt['elements'], 2)
        self.assertEqual(receipt['dependency_links'], [{'removed_position': 1, 'incoming_position': 0, 'same_package_name': True}])
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertFalse(receipt['runtime_count_correction_observed']); self.assertFalse(receipt['installation_authorized'])
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'native_test_seen': True, 'finite_model_not_vendor_database': True}

    def test_post_test_dependency_change_withholds_json_preserves_pointer_and_cleanup(self):
        self.prepare(userland_removal=True, element_changed_dependency=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('ordered observations changed across TEST', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': result.returncode, 'stderr': result.stderr, 'stdout': result.stdout, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'finite_model_not_vendor_database': True}

    def test_foreign_dependency_refuses_before_test_without_freeing_borrowed_result(self):
        self.prepare(userland_removal=True, element_foreign_dependency=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('outside the complete borrowed handle set', result.stderr); self.assertEqual(result.stdout, '')
        self.assertNotIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)

    def test_empty_current_batch_does_not_claim_package_test_or_positive_elements(self):
        self.prepare(empty=True); proof = json.loads(self.shell().stdout); receipt = proof['transaction_element_observation']
        self.assertFalse(proof['rpm_test_performed']); self.assertEqual(receipt['elements'], 0)
        self.assertEqual(receipt['new_rpm_api_calls'], 24); self.assertFalse(receipt['current_ordered_elements_observed'])


if __name__ == '__main__': unittest.main()

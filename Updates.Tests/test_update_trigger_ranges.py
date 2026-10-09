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
import test_update_trigger_conditions as conditions
import test_update_trigger_prefixes as prefixes
import test_update_triggers as triggers


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'Updates.Tests/rpm_range_model.c'
VERSION_MODEL = ROOT / 'Updates.Tests/rpm_version_model.c'


def namespace(): return prefixes.library()


class RangeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-range-api-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.root = Path(temporary.name)
        cls.library = cls.root / 'librpm-range-model.so'; cls.missing = cls.root / 'librpm-range-missing.so'
        cls.prefix = 'const char *RPMVERSION="4.18.2";\n'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', str(VERSION_MODEL), str(MODEL), '-o', str(cls.library)],
                       input=cls.prefix, text=True, capture_output=True, check=True)
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.missing)],
                       input=cls.prefix, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library))
        for name in ('rangeModelAllocated', 'rangeModelFreed', 'rangeModelOverlaps'):
            getattr(cls.lib, name).restype = C.c_uint; getattr(cls.lib, name).argtypes = ()
        cls.lib.rangeModelReset.argtypes = (); cls.lib.rangeModelReset.restype = None
        cls.namespace = namespace(); ordinary = cls.namespace['C'].CDLL
        cls.namespace['C'] = type('DeliveredC', (), {name: getattr(C, name) for name in
            ('sizeof', 'c_void_p', 'c_ulong', 'c_int', 'c_uint', 'c_char_p')})
        cls.namespace['C'].CDLL = staticmethod(lambda name, **options: ordinary(str(cls.library), **options))

    def setUp(self): self.lib.rangeModelReset()

    def compare(self): return self.namespace['trigger_range_native']()

    def test_all_seventeen_participation_vectors_and_reverse_self_relations(self):
        compare = self.compare()
        for left, right, mask, expected in self.namespace['TRIGGER_RANGE_PROBES']:
            with self.subTest(left=left, right=right, mask=mask):
                self.assertEqual([compare(left, 8, right, mask), compare(right, mask, left, 8),
                                  compare(left, 8, left, 8), compare(right, mask, right, mask)], [expected, expected, 1, 1])
        self.assertEqual(self.lib.rangeModelAllocated(), self.lib.rangeModelFreed())

    def test_native_parser_preserves_omitted_epoch_and_release(self):
        compare = self.compare()
        self.assertEqual(compare('0:1.0-1', 8, '1.0', 8), 1)
        self.assertEqual(compare('1.0-2', 8, '1.0', 2), 0)
        self.assertEqual(self.lib.rangeModelAllocated(), self.lib.rangeModelFreed())

    def test_field_mismatch_refuses_and_retires_allocated_handle(self):
        with patch.dict(os.environ, {'S4_RANGE_MODEL_FAULT': 'fields'}), self.assertRaisesRegex(ValueError, 'parsed fields differ'):
            self.compare()('1.0-1', 8, '1.0', 8)
        self.assertEqual(self.lib.rangeModelAllocated(), 1); self.assertEqual(self.lib.rangeModelFreed(), 1)

    def test_first_and_second_parse_failures_retire_every_successful_allocation(self):
        for fault, allocated in (('parse', 0), ('second-parse', 1)):
            self.lib.rangeModelReset()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_RANGE_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'parse failed'):
                self.compare()('1.0-1', 8, '1.0', 8)
            self.assertEqual(self.lib.rangeModelAllocated(), allocated); self.assertEqual(self.lib.rangeModelFreed(), allocated)

    def test_alias_handle_refuses_without_double_free(self):
        with patch.dict(os.environ, {'S4_RANGE_MODEL_FAULT': 'alias'}), self.assertRaisesRegex(ValueError, 'unexpectedly alias'):
            self.compare()('1.0-1', 8, '1.0', 8)
        self.assertEqual(self.lib.rangeModelAllocated(), 1); self.assertEqual(self.lib.rangeModelFreed(), 1)

    def test_nonboolean_native_result_refuses_after_both_handles_are_retired(self):
        with patch.dict(os.environ, {'S4_RANGE_MODEL_FAULT': 'invalid'}), self.assertRaisesRegex(ValueError, 'overlap result is unsupported'):
            self.compare()('1.0-1', 8, '1.0', 8)
        self.assertEqual(self.lib.rangeModelAllocated(), 2); self.assertEqual(self.lib.rangeModelFreed(), 2)

    def test_cleanup_refusal_still_calls_both_frees_and_withholds_result(self):
        with patch.dict(os.environ, {'S4_RANGE_MODEL_FAULT': 'free'}), self.assertRaisesRegex(ValueError, 'cleanup failed'):
            self.compare()('1.0-1', 8, '1.0', 8)
        self.assertEqual(self.lib.rangeModelFreed(), 2)

    def test_unsupported_abi_defers_before_library_open(self):
        with patch.object(self.namespace['platform'], 'machine', return_value='riscv64'), self.assertRaisesRegex(ValueError, 'ABI is unsupported'):
            self.compare()

    def test_missing_native_symbol_defers_without_allocating(self):
        original = self.namespace['C'].CDLL
        self.namespace['C'].CDLL = staticmethod(lambda name, **options: C.CDLL(str(self.missing), **options))
        try:
            with self.assertRaisesRegex(ValueError, 'symbol is missing'): self.compare()
        finally: self.namespace['C'].CDLL = original
        self.assertEqual(self.lib.rangeModelAllocated(), 0)

    def test_unvetted_version_receipt_refuses_before_parsing(self):
        slot = C.c_void_p.in_dll(self.lib, 'RPMVERSION'); before = slot.value
        changed = C.create_string_buffer(b'4.99-model'); slot.value = C.addressof(changed)
        try:
            with self.assertRaisesRegex(ValueError, 'version is not vetted'): self.compare()
        finally: slot.value = before
        self.assertEqual(self.lib.rangeModelAllocated(), 0)

    def test_invalid_flags_and_empty_evr_do_not_reach_native_overlap(self):
        for left, flags in (('1', True), ('1', 0), ('1', 6), ('', 8)):
            with self.subTest(left=left, flags=flags), self.assertRaises(ValueError): self.compare()(left, flags, '1', 8)
        self.assertEqual(self.lib.rangeModelOverlaps(), 0)


class RangeProofTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    replace_owner = conditions.ConditionProofTests.replace_owner

    @classmethod
    def setUpClass(cls):
        RangeNativeTests.setUpClass.__func__(cls)
        cls.compare = staticmethod(cls.namespace['trigger_range_native']())

    def make_proof(self, version=b'1-1', mask=8):
        proof = self.proof()
        self.replace_owner(proof, conditions.entries(names=(b'fixture', b'future'), versions=(version, b'1-1'), masks=(mask, 8)))
        return proof

    def observe(self, proof, factory=None):
        proof = self.namespace['trigger_observe'](proof)
        return self.namespace['trigger_range_observe'](proof, factory or (lambda: self.compare))

    def test_same_name_installed_and_incoming_ranges_bind_all_source_identities(self):
        proof = self.make_proof(); result = self.observe(proof)['trigger_range_observation']
        self.assertEqual(result['pairs_compared'], 2); self.assertTrue(result['native_participation_checked'])
        old, new = result['conditions']
        self.assertEqual(old['sources_compared'][0]['source']['kind'], 'installed')
        self.assertEqual(old['sources_compared'][0]['source']['instance'], 1)
        self.assertFalse(old['sources_compared'][0]['range_overlap'])
        self.assertEqual(new['sources_compared'][0]['source']['file'], 'packages/0.rpm')
        self.assertTrue(new['sources_compared'][0]['range_overlap'])
        self.assertEqual(new['sources_compared'][0]['source']['header_sha256'], proof['effects']['incoming'][0]['header_sha256'])

    def test_missing_same_name_source_does_not_manufacture_native_comparison(self):
        proof = self.make_proof(); self.replace_owner(proof, conditions.entries(names=(b'absent', b'absent'), versions=(b'1', b'1')))
        result = self.observe(proof, lambda: self.fail('native factory called without source pairs'))['trigger_range_observation']
        self.assertEqual(result['pairs_compared'], 0); self.assertFalse(result['observed_evr_ranges_compared'])
        self.assertEqual(result['native_comparator_invocations'], 0)

    def test_unversioned_conditions_stay_uncompared_and_do_not_load_library(self):
        proof = self.make_proof(); self.replace_owner(proof, conditions.entries(versions=(b'', b''), masks=(0, 0)))
        result = self.observe(proof, lambda: self.fail('unversioned condition loaded library'))['trigger_range_observation']
        self.assertEqual(result['ordinary_conditions'], 2); self.assertEqual(result['pairs_compared'], 0)
        self.assertTrue(all(not value['versioned_range'] for value in result['conditions']))
        self.assertFalse(result['unversioned_conditions_evaluated'])

    def test_file_only_and_no_trigger_batches_withhold_range_participation(self):
        for proof in (self.proof(), self.proof(trigger=False, incoming=False)):
            result = self.observe(proof, lambda: self.fail('file/no-trigger library call'))['trigger_range_observation']
            self.assertEqual(result['ordinary_conditions'], 0); self.assertFalse(result['native_participation_checked'])

    def test_all_sixteen_policy_authority_flags_remain_false(self):
        result = self.observe(self.make_proof())['trigger_range_observation']
        for name in ('unversioned_conditions_evaluated', 'actual_provides_observed', 'package_trigger_matches_observed',
                     'transaction_temporal_sources_selected', 'prefix_matches_observed', 'trigger_selection_complete',
                     'execution_order_complete', 'script_execution_plan_complete', 'installed_headers_authenticated',
                     'native_library_identity_authenticated', 'script_policy_satisfied', 'removal_policy_satisfied',
                     'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready'):
            self.assertIs(result[name], False, name)

    def test_positive_zero_and_invalid_comparator_models_cannot_pass_participation(self):
        for value in (1, 0, 42, True):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'participation|result is unsupported'):
                self.observe(self.make_proof(), lambda: lambda *args: value)

    def test_unknown_relevant_architecture_refuses_but_unrelated_identity_is_not_parsed(self):
        proof = self.make_proof(); owner = proof['effects']['incoming'][0]
        owner['nevra'] = 'future-1-1.(none)'; proof['additions'][0]['nevra'] = owner['nevra']
        with self.assertRaisesRegex(ValueError, 'architecture/identity is unsupported'): self.observe(proof)
        proof = self.make_proof(); self.replace_owner(proof, conditions.entries(names=(b'fixture', b'fixture'), versions=(b'1', b'1')))
        owner = proof['effects']['incoming'][0]; owner['nevra'] = 'future-1-1.(none)'; proof['additions'][0]['nevra'] = owner['nevra']
        self.observe(proof)

    def test_pair_bound_refuses_before_any_native_factory_in_scaled_model(self):
        previous = self.namespace['TRIGGER_RANGE_LIMIT']; self.namespace['TRIGGER_RANGE_LIMIT'] = 1
        try:
            with self.assertRaisesRegex(ValueError, 'pairs exceed'): self.observe(self.make_proof(), lambda: self.fail('factory before bound'))
        finally: self.namespace['TRIGGER_RANGE_LIMIT'] = previous

    def test_full_declaration_baseline_and_inventory_commitments_survive(self):
        proof = self.make_proof(); result = self.observe(proof)['trigger_range_observation']
        self.assertEqual(result['declaration_sha256'], proof['trigger_condition_observation']['owners_sha256'])
        self.assertEqual(result['baseline_sha256'], proof['baseline']['sha256'])
        self.assertEqual(result['inventory_sha256'], proof['effects']['installed_versions']['entries_sha256'])
        self.assertEqual(result['native_comparator_invocations'], 4 * 17 + 2 * 2)


class RangePrivateTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    setUp = triggers.TriggerPrivateInputTests.setUp
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_file_only_snapshot_binds_four_receipts_without_loading_native_ranges(self):
        material = self.path.read_bytes(); result = json.loads(self.run_guard().stdout)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation', 'trigger_range_observation'):
            self.assertEqual(result[name]['input_sha256'], hashlib.sha256(material).hexdigest())
        self.assertFalse(result['trigger_range_observation']['native_participation_checked'])
        self.assertEqual(self.path.read_bytes(), material)

    def test_stale_range_receipt_cannot_replace_missing_raw_declarations(self):
        proof = self.proof(); proof['trigger_range_observation'] = {'native_participation_checked': True}
        del proof['effects']['installed_script_owners'][0]['trigger_condition_bytes']
        self.path.write_text(json.dumps(proof)); self.run_guard(expected=75)


class RangePipelineTests(unittest.TestCase):
    command = conditions.ConditionPipelineTests.command
    configure = conditions.ConditionPipelineTests.configure
    calls = conditions.ConditionPipelineTests.calls
    setUp = conditions.ConditionPipelineTests.setUp
    header = conditions.ConditionPipelineTests.header
    prepare = conditions.ConditionPipelineTests.prepare
    native_calls = conditions.ConditionPipelineTests.native_calls
    shell = conditions.ConditionPipelineTests.shell
    setUpClass = classmethod(conditions.ConditionPipelineTests.setUpClass.__func__)

    def test_fresh_test_records_false_epoch_range_results_without_turning_them_into_permission(self):
        self.prepare(condition_ordinary=True, userland_removal=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout); receipt = proof['trigger_range_observation']
        self.assertEqual(receipt['pairs_compared'], 2); self.assertTrue(receipt['native_participation_checked'])
        self.assertEqual([entry['range_overlap'] for entry in receipt['conditions'][0]['sources_compared']], [False, False])
        self.assertFalse(receipt['package_trigger_matches_observed']); self.assertFalse(proof['installation_authorized'])
        source = copy.deepcopy(proof)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation', 'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation', 'header_input_observation', 'header_match_observation', 'trigger_first_observation', 'header_iteration_observation', 'trigger_count_observation', 'trigger_argument_observation', 'trigger_iterator_observation', 'trigger_walk_observation', 'transaction_element_observation', 'psm_goal_observation', 'psm_input_observation'): source.pop(name)
        self.assertEqual(receipt['input_sha256'], hashlib.sha256((json.dumps(source, sort_keys=True) + '\n').encode()).hexdigest())
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_native_participation_fault_refuses_after_test_without_output_or_pointer_change(self):
        self.prepare(condition_ordinary=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export S4_RANGE_MODEL_FAULT=positive; s4_check_update_effects', expected=75)
        self.assertIn('trigger range native participation control failed', result.stderr); self.assertIn('run 1', self.native_calls())
        self.assertEqual(result.stdout, ''); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_range_fault_keeps_existing_effects_component_pending(self):
        self.prepare(condition_ordinary=True)
        self.shell('export S4_RANGE_MODEL_FAULT=zero; s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())


if __name__ == '__main__': unittest.main()

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
import test_update_provides as provides
import test_update_trigger_conditions as conditions
import test_update_trigger_prefixes as prefixes
import test_update_trigger_ranges as ranges
import test_update_triggers as triggers


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'Updates.Tests/rpm_dependency_model.c'


class ProviderNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-dependency-api-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.root = Path(temporary.name)
        cls.library = cls.root / 'librpm-dependency-model.so'; cls.missing = cls.root / 'missing.so'
        source = 'const char *RPMVERSION="4.18.2";\n'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', str(ranges.VERSION_MODEL),
                        str(ranges.MODEL), str(MODEL), '-o', str(cls.library)],
                       input=source, text=True, capture_output=True, check=True)
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.missing)],
                       input=source, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library))
        for name in ('dependencyModelAllocated', 'dependencyModelFreed', 'dependencyModelCompared'):
            getattr(cls.lib, name).restype = C.c_uint; getattr(cls.lib, name).argtypes = ()
        cls.lib.dependencyModelReset.restype = None; cls.lib.dependencyModelReset.argtypes = ()
        cls.namespace = prefixes.library(); ordinary = cls.namespace['C'].CDLL
        cls.namespace['C'] = type('DeliveredC', (), {name: getattr(C, name) for name in
            ('sizeof', 'c_void_p', 'c_ulong', 'c_int', 'c_uint', 'c_char_p')})
        cls.namespace['C'].CDLL = staticmethod(lambda name, **options: ordinary(str(cls.library), **options))

    def setUp(self): self.lib.dependencyModelReset()

    def compare(self): return self.namespace['provider_native']()

    def test_all_twenty_five_vectors_check_forward_reverse_and_both_self_relations(self):
        compare = self.compare()
        for left, right, expected in self.namespace['PROVIDER_PROBES']:
            with self.subTest(left=left, right=right):
                self.assertEqual([compare(left, right), compare(right, left), compare(left, left), compare(right, right)],
                                 [expected, expected, 1, 1])
        self.assertEqual(len(self.namespace['PROVIDER_PROBES']), 25)
        self.assertEqual(self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed())

    def test_wrong_names_do_not_overlap_even_when_both_dependencies_are_unversioned(self):
        self.assertEqual(self.compare()(('left', '', 0), ('right', '', 0)), 0)
        self.assertEqual(self.compare()(('left', '', 0), ('left', '1', 8)), 1)

    def test_full_uint32_flags_and_omitted_epoch_release_are_read_back_without_normalization(self):
        self.assertEqual(self.compare()(('probe', '0:1.0-1', 0x80000008), ('probe', '1.0', 65536 | 8)), 1)
        self.assertEqual(self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed())

    def test_first_and_second_allocation_failure_retire_only_owned_successful_handles(self):
        for fault, count in (('allocate', 0), ('second-allocate', 1)):
            self.lib.dependencyModelReset()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'allocation failed'):
                self.compare()(('probe', '1', 8), ('probe', '1', 8))
            self.assertEqual((self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed()), (count, count))

    def test_alias_handle_refuses_without_double_free(self):
        with patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': 'alias'}), self.assertRaisesRegex(ValueError, 'unexpectedly alias'):
            self.compare()(('probe', '1', 8), ('probe', '1', 8))
        self.assertEqual((self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed()), (1, 1))

    def test_every_native_identity_receipt_field_is_required_before_comparison(self):
        for fault in ('count', 'index', 'tag', 'name', 'evr', 'flags'):
            self.lib.dependencyModelReset()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'receipt differs'):
                self.compare()(('probe', '1', 8), ('probe', '1', 8))
            self.assertEqual(self.lib.dependencyModelCompared(), 0)
            self.assertEqual((self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed()), (1, 1))

    def test_post_compare_receipt_change_refuses_and_retires_both_handles(self):
        with patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': 'changed'}), self.assertRaisesRegex(ValueError, 'changed during comparison'):
            self.compare()(('probe', '1', 8), ('probe', '1', 8))
        self.assertEqual((self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed()), (2, 2))

    def test_nonboolean_native_result_refuses_after_owned_cleanup(self):
        with patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': 'invalid'}), self.assertRaisesRegex(ValueError, 'overlap result is unsupported'):
            self.compare()(('probe', '1', 8), ('probe', '1', 8))
        self.assertEqual(self.lib.dependencyModelFreed(), 2)

    def test_cleanup_failure_withholds_success_and_still_retires_both_handles(self):
        with patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': 'free'}), self.assertRaisesRegex(ValueError, 'cleanup failed'):
            self.compare()(('probe', '1', 8), ('probe', '1', 8))
        self.assertEqual(self.lib.dependencyModelFreed(), 2)

    def test_missing_native_symbol_defers_before_allocation(self):
        original = self.namespace['C'].CDLL
        self.namespace['C'].CDLL = staticmethod(lambda name, **options: C.CDLL(str(self.missing), **options))
        try:
            with self.assertRaisesRegex(ValueError, 'symbol is missing'): self.compare()
        finally: self.namespace['C'].CDLL = original
        self.assertEqual(self.lib.dependencyModelAllocated(), 0)

    def test_unvetted_version_and_unsupported_abi_defer_before_allocation(self):
        slot = C.c_void_p.in_dll(self.lib, 'RPMVERSION'); before = slot.value
        changed = C.create_string_buffer(b'4.99-model'); slot.value = C.addressof(changed)
        try:
            with self.assertRaisesRegex(ValueError, 'version is not vetted'): self.compare()
        finally: slot.value = before
        with patch.object(self.namespace['platform'], 'machine', return_value='riscv64'), self.assertRaisesRegex(ValueError, 'ABI is unsupported'):
            self.compare()
        self.assertEqual(self.lib.dependencyModelAllocated(), 0)

    def test_invalid_literal_serial_flag_evr_and_boolean_refuse_before_allocation(self):
        for value in (('probe', '', 8), ('probe', '1', 0), ('probe', '1', 9), ('probe', '1', True),
                      ('probe', '01:1', 8), ('probe', '1', 6), ('probe\n', '1', 8), ('probe', '\xff', 8)):
            with self.subTest(value=value), self.assertRaises((ValueError, UnicodeError)):
                self.compare()(value, ('probe', '1', 8))
        self.assertEqual(self.lib.dependencyModelAllocated(), 0)


class ProviderProofTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof

    @classmethod
    def setUpClass(cls):
        ProviderNativeTests.setUpClass.__func__(cls)
        cls.native_compare = staticmethod(cls.namespace['provider_native']())

    def make_proof(self, versions=(b'1.0', b''), flags=(8, 0), names=(b'virtual-capability', b'opaque\xff')):
        proof = self.proof(); owner = proof['effects']['installed_script_owners'][0]
        material = effects.exported(conditions.entries(names=(b'virtual-capability', b'absent'), versions=(b'2.0', b''), masks=(4, 0))
                                    + provides.entries(names, versions, flags))
        audited = self.namespace['audit_header'](material)
        owner.update(audited, provides=self.namespace['provides_export'](material, audited),
            file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited),
            trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        self.rebind(proof)
        return proof

    def rebind(self, proof):
        owner = proof['effects']['installed_script_owners'][0]
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner}, proof['baseline'])
        proof['effects']['installed_provides'] = [{field: owner[field] for field in (*self.namespace['INSTALLED_VERSION_FIELDS'], 'provides')}]

    def observe(self, proof, factory=None):
        return self.namespace['provider_observe'](self.namespace['trigger_observe'](proof), factory or (lambda: self.native_compare))

    def test_provider_name_differs_from_package_name_and_false_overlap_still_publishes_qualified_observation(self):
        proof = self.make_proof(); receipt = self.observe(proof)['provider_match_observation']
        self.assertEqual(receipt['pairs_compared'], 1)
        compared = receipt['conditions'][0]['sources_compared'][0]
        self.assertEqual(compared['source']['owner']['name'], 'fixture')
        self.assertEqual(receipt['conditions'][0]['name'], 'virtual-capability')
        self.assertIs(compared['declared_dependency_overlap'], False)
        self.assertFalse(receipt['package_source_name_gate_satisfied'])
        self.assertEqual(receipt['native_comparator_invocations'], 102)

    def test_unversioned_provider_matches_versioned_condition_without_inventing_an_evr(self):
        receipt = self.observe(self.make_proof(versions=(b'', b''), flags=(0, 0)))['provider_match_observation']
        source = receipt['conditions'][0]['sources_compared'][0]
        self.assertTrue(source['declared_dependency_overlap'])
        self.assertEqual(source['source']['evr'], ''); self.assertIsNone(source['source']['evr_parts'])

    def test_duplicate_provides_positions_are_all_retained_with_distinct_results(self):
        proof = self.make_proof(names=(b'virtual-capability', b'virtual-capability'), versions=(b'1.0', b'9:1.0'), flags=(8, 8))
        receipt = self.observe(proof)['provider_match_observation']
        compared = receipt['conditions'][0]['sources_compared']
        self.assertEqual([row['source']['position'] for row in compared], [0, 1])
        self.assertEqual([row['declared_dependency_overlap'] for row in compared], [False, True])

    def test_all_installed_removed_and_incoming_sources_stay_unselected_and_identity_bound(self):
        proof = self.make_proof(); owner = proof['effects']['installed_script_owners'][0]
        proof['effects']['removals'] = [{**copy.deepcopy(owner), 'classification': 'other-removal'}]
        proof['removals'] = [owner['nevra']]
        incoming = proof['effects']['incoming'][0]
        material = effects.exported(provides.entries((b'virtual-capability',), (b'',), (0,)))
        audited = self.namespace['audit_header'](material)
        incoming.update(audited, provides=self.namespace['provides_export'](material, audited))
        receipt = self.observe(proof)['provider_match_observation']
        compared = receipt['conditions'][0]['sources_compared']
        self.assertEqual([row['source']['owner']['kind'] for row in compared], ['installed', 'incoming'])
        self.assertEqual(compared[0]['source']['owner']['instance'], 1)
        self.assertEqual(compared[1]['source']['owner']['sha256'], proof['additions'][0]['sha256'])
        self.assertFalse(receipt['transaction_temporal_sources_selected'])

    def test_unrelated_nonascii_name_and_unsupported_evr_flags_remain_opaque(self):
        receipt = self.observe(self.make_proof(versions=(b'1.0', b'\xff$(false)'), flags=(8, 2**32 - 1)))['provider_match_observation']
        self.assertEqual(receipt['pairs_compared'], 1)
        self.assertNotIn('opaque', json.dumps(receipt))

    def test_relevant_evr_masks_serial_and_ascii_profile_refuse_before_native_factory(self):
        for version, flags in ((b'', 8), (b'1', 0), (b'1', 9), (b'1', 6), (b'01:1', 8), (b'\xff', 8)):
            with self.subTest(version=version, flags=flags), self.assertRaises((ValueError, UnicodeError)):
                self.observe(self.make_proof(versions=(version, b''), flags=(flags, 0)), lambda: self.fail('native factory before declaration admission'))

    def test_missing_projections_cannot_borrow_stale_positive_provider_receipt(self):
        proof = self.make_proof(); del proof['effects']['installed_provides']
        proof['provider_match_observation'] = {'declared_dependency_ranges_compared': True}
        with self.assertRaises(KeyError): self.observe(proof, lambda: self.fail('factory before raw correspondence'))

    def test_no_pairs_and_file_only_batches_load_no_dependency_library(self):
        proof = self.proof(); receipt = self.observe(proof, lambda: self.fail('no-pair factory'))['provider_match_observation']
        self.assertEqual((receipt['pairs_compared'], receipt['native_comparator_invocations']), (0, 0))
        self.assertFalse(receipt['declared_dependency_ranges_compared'])
        proof = self.make_proof(names=(b'unrelated', b'opaque\xff'))
        receipt = self.observe(proof, lambda: self.fail('unmatched factory'))['provider_match_observation']
        self.assertEqual([row['sources_compared'] for row in receipt['conditions']], [[], []])

    def test_pair_limit_precedes_native_work_and_withholds_partial_receipt(self):
        previous = self.namespace['PROVIDER_PAIR_LIMIT']; self.namespace['PROVIDER_PAIR_LIMIT'] = 0
        try:
            proof = self.make_proof()
            with self.assertRaisesRegex(ValueError, 'pairs exceed'):
                self.observe(proof, lambda: self.fail('factory before bound'))
            self.assertNotIn('provider_match_observation', proof)
        finally: self.namespace['PROVIDER_PAIR_LIMIT'] = previous

    def test_all_positive_negative_nonboolean_and_asymmetric_participation_deliveries_refuse(self):
        for fault in ('positive', 'zero', 'invalid', 'asymmetric'):
            proof = self.make_proof()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'participation|result is unsupported'):
                self.observe(proof)
            self.assertNotIn('provider_match_observation', proof)

    def test_actual_pair_asymmetry_is_refused_after_successful_participation(self):
        calls = 0
        def compare(left, right):
            nonlocal calls
            calls += 1
            if calls <= 100: return self.native_compare(left, right)
            return int(calls == 101)
        proof = self.make_proof()
        with self.assertRaisesRegex(ValueError, 'overlap is not symmetric'):
            self.observe(proof, lambda: compare)
        self.assertEqual(calls, 102); self.assertNotIn('provider_match_observation', proof)

    def test_bad_later_pair_withholds_entire_receipt_after_earlier_pair_succeeded(self):
        calls = 0
        def compare(left, right):
            nonlocal calls
            calls += 1
            return self.native_compare(left, right) if calls <= 102 else True
        proof = self.make_proof(names=(b'virtual-capability', b'virtual-capability'), versions=(b'1.0', b'9:1.0'), flags=(8, 8))
        with self.assertRaisesRegex(ValueError, 'comparison result is unsupported'):
            self.observe(proof, lambda: compare)
        self.assertEqual(calls, 103); self.assertNotIn('provider_match_observation', proof)

    def test_legacy_serial_bit_on_relevant_condition_defers_before_dependency_factory(self):
        proof = self.make_proof(); owner = proof['effects']['installed_script_owners'][0]
        material = effects.exported(conditions.entries(names=(b'virtual-capability', b'absent'),
            versions=(b'2.0', b''), masks=(4 | 1, 0)) + provides.entries((b'virtual-capability',), (b'1.0',), (8,)))
        audited = self.namespace['audit_header'](material)
        owner.update(audited, provides=self.namespace['provides_export'](material, audited),
            file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited),
            trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        self.rebind(proof)
        with self.assertRaisesRegex(ValueError, 'legacy serial bit'):
            self.observe(proof, lambda: self.fail('dependency factory before serial admission'))

    def test_false_and_true_results_bind_complete_records_and_all_prior_input_commitments(self):
        proof = self.make_proof(); receipt = self.observe(proof)['provider_match_observation']
        material = json.dumps(receipt['conditions'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((receipt['conditions_bytes'], receipt['conditions_sha256']), (len(material), hashlib.sha256(material).hexdigest()))
        self.assertEqual(receipt['provides_sha256'], proof['provides_observation']['owners_sha256'])
        self.assertEqual(receipt['declaration_sha256'], proof['trigger_condition_observation']['owners_sha256'])
        self.assertEqual(receipt['baseline_sha256'], proof['baseline']['sha256'])
        self.assertEqual(receipt['inventory_sha256'], proof['effects']['installed_versions']['entries_sha256'])

    def test_all_sixteen_authority_flags_remain_false_even_on_positive_overlap(self):
        receipt = self.observe(self.make_proof(versions=(b'', b''), flags=(0, 0)))['provider_match_observation']
        flags = ('actual_header_dependency_matches_observed', 'package_source_name_gate_satisfied', 'provider_architectures_selected',
            'transaction_temporal_sources_selected', 'trigger_phase_selected', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'installed_headers_authenticated', 'native_library_identity_authenticated',
            'script_policy_satisfied', 'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')
        for name in flags: self.assertIs(receipt[name], False, name)


class ProviderPrivateTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    setUp = triggers.TriggerPrivateInputTests.setUp
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_file_only_snapshot_binds_six_receipts_and_preserves_input(self):
        material = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation',
                     'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation'):
            self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(self.path.read_bytes(), material)
        self.assertFalse(proof['provider_match_observation']['native_participation_checked'])

    def test_stale_success_cannot_replace_missing_current_header_projection_on_private_path(self):
        proof = self.proof(); proof['provider_match_observation'] = {'declared_dependency_ranges_compared': True}
        del proof['effects']['installed_provides']; self.path.write_text(json.dumps(proof)); material = self.path.read_bytes()
        self.assertIn('installed_provides', self.run_guard(expected=75).stderr)
        self.assertEqual(self.path.read_bytes(), material)


class ProviderPipelineTests(unittest.TestCase):
    command = conditions.ConditionPipelineTests.command
    configure = conditions.ConditionPipelineTests.configure
    calls = conditions.ConditionPipelineTests.calls
    setUp = conditions.ConditionPipelineTests.setUp
    header = conditions.ConditionPipelineTests.header
    prepare = conditions.ConditionPipelineTests.prepare
    native_calls = conditions.ConditionPipelineTests.native_calls
    shell = conditions.ConditionPipelineTests.shell

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-provider-pipeline-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.library = Path(temporary.name) / 'model.so'
        source = effects.LIBRARY.replace('uint32_t count=setting("trigger_missing_priority")?7:8;',
            'uint32_t count=setting("trigger_missing_priority")||setting("condition_ordinary")?7:8;\n'
            '    if(setting("condition_ordinary")) { uint32_t ordinary[]={1065,1092,5027,1066,1067,1068,1069,0};memcpy(tags,ordinary,sizeof(tags)); }')
        source = source.replace('NULL,"/usr/lib", "",NULL,NULL,NULL',
            'NULL,setting("condition_ordinary")?"userland":"/usr/lib",setting("condition_ordinary")?"2:1.0~rc1-3.azl3":"",NULL,NULL,NULL')
        source = source.replace('0,0,0,0,0,65536,setting("trigger_bad_index")',
            '0,0,0,0,0,65536|(setting("condition_ordinary")?12:0),setting("trigger_bad_index")')
        model = provides.PROVIDES_MODEL.replace('incoming(h)?"1-1":"9:7-3"',
            'incoming(h)?(setting("provider_positive")?"9:7-3":"1-1"):"9:7-3"')
        source = source.replace('void *headerExport(', 'void *fixtureProvidesOriginalExport(') + model
        source += ranges.VERSION_MODEL.read_text() + ranges.MODEL.read_text() + MODEL.read_text()
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=source, text=True, capture_output=True, check=True)

    def test_current_test_records_positive_provided_dependency_and_six_input_hashes_without_authority(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['provider_match_observation']; compared = receipt['conditions'][0]['sources_compared']
        self.assertEqual(receipt['pairs_compared'], 1); self.assertTrue(compared[0]['declared_dependency_overlap'])
        self.assertEqual(compared[0]['source']['evr'], '9:7-3')
        self.assertEqual(compared[0]['source']['owner']['sha256'], proof['additions'][0]['sha256'])
        original = copy.deepcopy(proof)
        names = ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation',
                 'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation')
        for name in names: original.pop(name)
        digest = hashlib.sha256((json.dumps(original, sort_keys=True) + '\n').encode()).hexdigest()
        for name in names: self.assertEqual(proof[name]['input_sha256'], digest)
        self.assertFalse(receipt['actual_header_dependency_matches_observed']); self.assertFalse(proof['installation_authorized'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_false_provided_dependency_is_an_observation_and_does_not_select_or_refuse_a_trigger(self):
        self.prepare(condition_ordinary=True); proof = json.loads(self.shell().stdout)
        compared = proof['provider_match_observation']['conditions'][0]['sources_compared']
        self.assertIs(compared[0]['declared_dependency_overlap'], False)
        self.assertFalse(proof['provider_match_observation']['trigger_selection_complete'])

    def test_native_participation_failure_after_test_withholds_output_and_preserves_pointer(self):
        self.prepare(condition_ordinary=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export S4_DEPENDENCY_MODEL_FAULT=positive; s4_check_update_effects', expected=75)
        self.assertIn('provider dependency native participation control failed', result.stderr)
        self.assertIn('run 1', self.native_calls()); self.assertEqual(result.stdout, '')
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_dependency_failure_keeps_existing_effects_component_pending(self):
        self.prepare(condition_ordinary=True)
        self.shell('export S4_DEPENDENCY_MODEL_FAULT=zero; s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())


if __name__ == '__main__': unittest.main()

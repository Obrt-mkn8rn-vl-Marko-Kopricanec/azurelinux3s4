import copy
import hashlib
import json
import unittest

import test_update_effects as effects
import test_update_provides as provides
import test_update_provider_matches as providers
import test_update_trigger_conditions as conditions
import test_update_triggers as triggers


RECEIPTS = ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation',
            'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation', 'header_input_observation', 'header_match_observation', 'trigger_first_observation', 'header_iteration_observation', 'trigger_count_observation', 'trigger_argument_observation', 'trigger_iterator_observation', 'trigger_walk_observation', 'transaction_element_observation', 'psm_goal_observation', 'psm_input_observation', 'psm_route_observation')
AUTHORITIES = ('actual_header_dependency_matches_observed', 'trigger_phase_selected',
    'transaction_temporal_sources_selected', 'provider_architectures_selected', 'trigger_eligibility_complete',
    'trigger_selection_complete', 'execution_order_complete', 'script_execution_plan_complete',
    'installed_headers_authenticated', 'native_library_identity_authenticated', 'script_policy_satisfied',
    'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')


class TriggerSourceProofTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    rebind = providers.ProviderProofTests.rebind
    setUpClass = classmethod(providers.ProviderProofTests.setUpClass.__func__)

    def make_proof(self, name=b'fixture', phase=65536, provide_names=None):
        proof = self.proof(); owner = proof['effects']['installed_script_owners'][0]
        entries = conditions.entries(names=(name, b'absent'), versions=(b'', b''), masks=(0, 0))
        entries = [(tag, kind, (tuple(phase for _ in values) if type(phase) is int else phase)
                    if tag == 1068 else values) for tag, kind, values in entries]
        if provide_names is not None:
            entries += provides.entries(provide_names, tuple(b'' for _ in provide_names), tuple(0 for _ in provide_names))
        material = effects.exported(entries); audited = self.namespace['audit_header'](material)
        owner.update(audited, provides=self.namespace['provides_export'](material, audited),
            file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited),
            trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        self.rebind(proof); return proof

    def observe(self, proof, factory=None):
        return self.namespace['trigger_source_observe'](self.namespace['trigger_observe'](proof),
            factory or (lambda: self.native_compare))['trigger_source_observation']

    def test_same_package_name_positive_dependency_is_only_true_in_its_declared_possible_phase(self):
        proof = self.make_proof(provide_names=(b'fixture',)); receipt = self.observe(proof)
        record = receipt['conditions'][0]; source = record['package_name_sources'][0]
        self.assertTrue(source['source_package_name_equal']); self.assertTrue(source['same_name_declared_provides_overlap'])
        self.assertEqual(record['declared_phase'], 'in')
        self.assertEqual([row['name_and_declared_provides_and_phase_overlap'] for row in source['possible_phase_predicates']],
                         [True, False, False, False])
        self.assertFalse(receipt['trigger_eligibility_complete']); self.assertFalse(receipt['trigger_phase_selected'])

    def test_virtual_capability_from_different_package_cannot_manufacture_source_name_match(self):
        receipt = self.observe(self.make_proof(b'virtual-capability', provide_names=(b'virtual-capability',)))
        record = receipt['conditions'][0]
        self.assertEqual(record['package_name_sources'], [])
        self.assertEqual(len(record['different_package_providers']), 1)
        row = record['different_package_providers'][0]
        self.assertTrue(row['declared_dependency_overlap']); self.assertIs(row['source_package_name_equal'], False)
        self.assertEqual(row['owner']['name'], 'fixture')
        self.assertFalse(receipt['source_package_names_compared'])

    def test_matching_package_without_declared_provides_is_retained_without_native_or_match_inference(self):
        receipt = self.observe(self.make_proof(), lambda: self.fail('no declared dependency pairs'))
        source = receipt['conditions'][0]['package_name_sources'][0]
        self.assertTrue(source['source_package_name_equal']); self.assertEqual(source['declared_provides_compared'], [])
        self.assertFalse(source['same_name_declared_provides_overlap'])
        self.assertTrue(all(not row['name_and_declared_provides_and_phase_overlap'] for row in source['possible_phase_predicates']))
        self.assertFalse(receipt['actual_header_dependency_matches_observed'])

    def test_all_four_declared_phase_masks_keep_single_phase_relationship_without_event_selection(self):
        for position, (mask, name) in enumerate(self.namespace['TRIGGER_SOURCE_PHASES']):
            with self.subTest(phase=name):
                receipt = self.observe(self.make_proof(phase=mask, provide_names=(b'fixture',)))
                record = receipt['conditions'][0]; source = record['package_name_sources'][0]
                self.assertEqual((record['declared_phase_mask'], record['declared_phase']), (mask, name))
                self.assertEqual([row['name_and_declared_provides_and_phase_overlap'] for row in source['possible_phase_predicates']],
                                 [i == position for i in range(4)])
                self.assertFalse(receipt['transaction_temporal_sources_selected'])

    def test_duplicate_provide_positions_remain_in_same_header_without_duplicate_source_pairs(self):
        receipt = self.observe(self.make_proof(provide_names=(b'fixture', b'fixture')))
        self.assertEqual(receipt['package_name_pairs'], 1)
        source = receipt['conditions'][0]['package_name_sources'][0]
        self.assertEqual([row['provide_position'] for row in source['declared_provides_compared']], [0, 1])
        self.assertTrue(all(row['declared_dependency_overlap'] for row in source['declared_provides_compared']))

    def test_same_nevra_distinct_installed_instances_are_not_collapsed(self):
        proof = self.make_proof(provide_names=(b'fixture',)); owner = proof['effects']['installed_script_owners'][0]
        other = {**copy.deepcopy(owner), 'instance': 2}; proof['effects']['installed_script_owners'].append(other)
        proof['baseline'] = {'headers': 2, 'sha256': hashlib.sha256(json.dumps(
            [(row['instance'], row['header_sha256']) for row in (owner, other)], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner, 2: other}, proof['baseline'])
        proof['effects']['installed_headers_observed'] = 2
        proof['effects']['installed_provides'] = [{field: row[field] for field in (*self.namespace['INSTALLED_VERSION_FIELDS'], 'provides')}
                                               for row in (owner, other)]
        receipt = self.observe(proof)
        self.assertEqual([row['owner']['instance'] for row in receipt['conditions'][0]['package_name_sources']], [1, 2])
        self.assertEqual(receipt['package_name_pairs'], 4)

    def test_removed_installed_source_remains_explicitly_unselected(self):
        proof = self.make_proof(provide_names=(b'fixture',)); owner = proof['effects']['installed_script_owners'][0]
        proof['effects']['removals'] = [{**copy.deepcopy(owner), 'classification': 'other-removal'}]; proof['removals'] = [owner['nevra']]
        receipt = self.observe(proof); source = receipt['conditions'][0]['package_name_sources'][0]
        self.assertTrue(source['observed_removal']); self.assertEqual(source['owner']['instance'], 1)
        self.assertFalse(receipt['transaction_temporal_sources_selected'])

    def test_incoming_source_binds_same_admitted_snapshot_without_temporal_selection(self):
        proof = self.make_proof(b'future'); incoming = proof['effects']['incoming'][0]
        material = effects.exported(provides.entries((b'future',), (b'',), (0,)))
        audited = self.namespace['audit_header'](material)
        incoming.update(audited, provides=self.namespace['provides_export'](material, audited))
        receipt = self.observe(proof); source = receipt['conditions'][0]['package_name_sources'][0]
        self.assertEqual(source['owner']['kind'], 'incoming')
        self.assertEqual(source['owner']['sha256'], proof['additions'][0]['sha256'])
        self.assertTrue(source['same_name_declared_provides_overlap']); self.assertFalse(source['observed_removal'])

    def test_scriptless_installed_source_is_included_by_complete_inventory(self):
        proof = self.make_proof(b'userland'); material = effects.exported(provides.entries((b'userland',), (b'',), (0,)))
        audited = self.namespace['audit_header'](material)
        source = {'instance': 2, 'name': 'userland', 'nevra': 'userland-0-1.x86_64',
                  'header_bytes': len(material), 'header_sha256': audited['header_sha256']}
        old = proof['effects']['installed_script_owners'][0]
        proof['baseline'] = {'headers': 2, 'sha256': hashlib.sha256(json.dumps(
            [(row['instance'], row['header_sha256']) for row in (old, source)], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: old, 2: source}, proof['baseline'])
        proof['effects']['installed_headers_observed'] = 2
        proof['effects']['installed_provides'].append({**source, 'provides': self.namespace['provides_export'](material, audited)})
        receipt = self.observe(proof)
        self.assertEqual(receipt['conditions'][0]['package_name_sources'][0]['owner']['instance'], 2)

    def test_case_sensitive_and_missing_source_names_have_no_package_candidate(self):
        for name in (b'Fixture', b'missing'):
            with self.subTest(name=name):
                receipt = self.observe(self.make_proof(name))
                self.assertEqual(receipt['conditions'][0]['package_name_sources'], [])
                self.assertFalse(receipt['source_package_names_compared'])
                self.assertTrue(receipt['declared_phase_relationships_observed'])

    def test_name_from_one_header_and_positive_provides_from_another_do_not_combine(self):
        proof = self.make_proof(); incoming = proof['effects']['incoming'][0]
        material = effects.exported(provides.entries((b'fixture',), (b'',), (0,)))
        audited = self.namespace['audit_header'](material)
        incoming.update(audited, provides=self.namespace['provides_export'](material, audited))
        record = self.observe(proof)['conditions'][0]
        own = record['package_name_sources'][0]; other = record['different_package_providers'][0]
        self.assertEqual(own['owner']['name'], 'fixture'); self.assertFalse(own['same_name_declared_provides_overlap'])
        self.assertEqual(other['owner']['name'], 'future'); self.assertTrue(other['declared_dependency_overlap'])
        self.assertFalse(any(row['name_and_declared_provides_and_phase_overlap'] for row in own['possible_phase_predicates']))

    def test_two_scripts_preserve_different_declared_phases_and_source_positions(self):
        receipt = self.observe(self.make_proof(phase=(65536, 33554432), provide_names=(b'fixture',)))
        records = receipt['conditions']
        self.assertEqual([(row['condition_position'], row['script_index'], row['declared_phase']) for row in records],
                         [(0, 1, 'in'), (1, 0, 'prein')])
        self.assertEqual(records[1]['package_name_sources'], [])

    def test_unsupported_higher_sense_bits_are_retained_without_phase_or_policy_approval(self):
        receipt = self.observe(self.make_proof(phase=65536 | 0x80000000, provide_names=(b'fixture',)))
        record = receipt['conditions'][0]
        self.assertEqual(record['declared_sense'], 65536 | 0x80000000)
        self.assertEqual(record['declared_phase_mask'], 65536)
        self.assertFalse(receipt['trigger_eligibility_complete']); self.assertFalse(receipt['trigger_phase_selected'])

    def test_name_pair_bound_withholds_new_receipt_after_accepted_comparisons(self):
        old = self.namespace['TRIGGER_SOURCE_PAIR_LIMIT']; self.namespace['TRIGGER_SOURCE_PAIR_LIMIT'] = 0
        try:
            proof = self.make_proof(provide_names=(b'fixture',))
            with self.assertRaisesRegex(ValueError, 'package-name pairs exceed'): self.observe(proof)
            self.assertNotIn('trigger_source_observation', proof)
        finally: self.namespace['TRIGGER_SOURCE_PAIR_LIMIT'] = old

    def test_exact_bound_is_admitted_and_output_counts_are_actual(self):
        old = self.namespace['TRIGGER_SOURCE_PAIR_LIMIT']; self.namespace['TRIGGER_SOURCE_PAIR_LIMIT'] = 1
        try:
            receipt = self.observe(self.make_proof(provide_names=(b'fixture',)))
            self.assertEqual((receipt['package_name_pairs'], receipt['ordinary_conditions'], receipt['source_headers']), (1, 2, 2))
        finally: self.namespace['TRIGGER_SOURCE_PAIR_LIMIT'] = old

    def test_file_only_zero_and_empty_batches_withhold_phase_and_name_observation(self):
        for trigger, incoming in ((True, True), (False, True), (False, False)):
            with self.subTest(trigger=trigger, incoming=incoming):
                receipt = self.observe(self.proof(trigger=trigger, incoming=incoming),
                    lambda: self.fail('file-only or empty comparator'))
                self.assertEqual(receipt['conditions'], []); self.assertFalse(receipt['declared_phase_relationships_observed'])
                self.assertFalse(receipt['source_package_names_compared']); self.assertEqual(receipt['package_name_pairs'], 0)

    def test_stale_positive_receipts_cannot_replace_current_raw_header_arrays(self):
        proof = self.make_proof(); proof['trigger_source_observation'] = {'source_package_names_compared': True}
        proof['provider_match_observation'] = {'declared_dependency_ranges_compared': True}; del proof['effects']['installed_provides']
        with self.assertRaises(KeyError): self.observe(proof, lambda: self.fail('factory before raw admission'))

    def test_phase_combination_and_missing_phase_refuse_in_fresh_accepted_array_guard(self):
        for phase in (0, 65536 | 131072):
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, 'phase'):
                self.observe(self.make_proof(phase=phase))

    def test_complete_output_and_source_universe_commitments_reconstruct(self):
        proof = self.make_proof(provide_names=(b'fixture',)); receipt = self.observe(proof)
        material = json.dumps(receipt['conditions'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((receipt['conditions_bytes'], receipt['conditions_sha256']), (len(material), hashlib.sha256(material).hexdigest()))
        sources = [{'owner': {key: value for key, value in row.items() if key not in ('source_tags', 'provides')},
                    'observed_removal': False} for row in proof['provides_observation']['owners']]
        source_material = json.dumps(sources, sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((receipt['sources_bytes'], receipt['sources_sha256']), (len(source_material), hashlib.sha256(source_material).hexdigest()))
        self.assertEqual(receipt['provider_comparisons_sha256'], proof['provider_match_observation']['conditions_sha256'])
        self.assertEqual(receipt['inventory_sha256'], proof['effects']['installed_versions']['entries_sha256'])

    def test_all_sixteen_authority_flags_stay_false_on_positive_static_predicate(self):
        receipt = self.observe(self.make_proof(provide_names=(b'fixture',)))
        for flag in AUTHORITIES: self.assertIs(receipt[flag], False, flag)


class TriggerSourcePrivateTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    setUp = triggers.TriggerPrivateInputTests.setUp
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_real_private_file_snapshot_binds_all_seven_receipts_and_stays_unchanged(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(proof['trigger_source_observation']['source_package_names_compared'])

    def test_private_missing_inventory_refuses_even_with_stale_source_and_provider_receipts(self):
        proof = self.proof(); del proof['effects']['installed_versions']
        proof['trigger_source_observation'] = {'source_package_names_compared': True}
        proof['provider_match_observation'] = {'native_participation_checked': True}
        self.path.write_text(json.dumps(proof)); before = self.path.read_bytes()
        self.assertIn('installed', self.run_guard(expected=75).stderr)
        self.assertEqual(self.path.read_bytes(), before)


class TriggerSourcePipelineTests(unittest.TestCase):
    command = providers.ProviderPipelineTests.command
    configure = providers.ProviderPipelineTests.configure
    calls = providers.ProviderPipelineTests.calls
    setUp = providers.ProviderPipelineTests.setUp
    header = providers.ProviderPipelineTests.header
    prepare = providers.ProviderPipelineTests.prepare
    native_calls = providers.ProviderPipelineTests.native_calls
    shell = providers.ProviderPipelineTests.shell
    setUpClass = classmethod(providers.ProviderPipelineTests.setUpClass.__func__)

    def test_current_test_positive_name_dependency_phase_join_preserves_all_seven_input_hashes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_source_observation']; record = receipt['conditions'][0]
        self.assertEqual([row['owner']['kind'] for row in record['package_name_sources']], ['installed', 'incoming'])
        self.assertFalse(record['package_name_sources'][0]['same_name_declared_provides_overlap'])
        source = record['package_name_sources'][1]
        self.assertEqual(source['owner']['name'], 'userland'); self.assertEqual(record['declared_phase_mask'], 65536)
        self.assertTrue(source['same_name_declared_provides_overlap'])
        self.assertEqual([row['name_and_declared_provides_and_phase_overlap'] for row in source['possible_phase_predicates']],
                         [True, False, False, False])
        original = copy.deepcopy(proof)
        for name in RECEIPTS: original.pop(name)
        digest = hashlib.sha256((json.dumps(original, sort_keys=True) + '\n').encode()).hexdigest()
        for name in RECEIPTS: self.assertEqual(proof[name]['input_sha256'], digest)
        for flag in AUTHORITIES: self.assertIs(receipt[flag], False, flag)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_current_test_false_dependency_keeps_name_candidate_without_eligibility(self):
        self.prepare(condition_ordinary=True); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_source_observation']; source = receipt['conditions'][0]['package_name_sources'][0]
        self.assertTrue(source['source_package_name_equal']); self.assertFalse(source['same_name_declared_provides_overlap'])
        self.assertFalse(any(row['name_and_declared_provides_and_phase_overlap'] for row in source['possible_phase_predicates']))
        self.assertFalse(receipt['trigger_eligibility_complete'])

    def test_source_pair_bound_after_current_test_refuses_json_and_preserves_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        script = "def limited_sources(proof):\n    global TRIGGER_SOURCE_PAIR_LIMIT\n    TRIGGER_SOURCE_PAIR_LIMIT = 0\n    return trigger_source_observe(proof)\n"
        ending = 'if trigger_execution:\n    raise SystemExit(trigger_main(psm_route_observe))\n'
        guard = triggers.emitted().replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',').replace(ending,
            script + 'if trigger_execution:\n    raise SystemExit(trigger_main(limited_sources))\n')
        self.assertIn(script, guard)
        model_path = self.root / 'source-bound-model.py'; model_path.write_text(guard)
        import shlex
        result = self.shell('s4_update_trigger_inputs_program() { cat ' + shlex.quote(str(model_path)) + '; }; s4_check_update_effects', expected=75)
        self.assertIn('trigger source package-name pairs exceed their bound', result.stderr)
        self.assertIn('run 1', self.native_calls()); self.assertEqual(result.stdout, '')
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'model': 'ONLY an explicit trusted source-pair limit delivery of zero in the current emitted parent',
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_existing_native_participation_refusal_cannot_publish_new_source_receipt(self):
        self.prepare(condition_ordinary=True)
        result = self.shell('export S4_DEPENDENCY_MODEL_FAULT=positive; s4_check_update_effects', expected=75)
        self.assertIn('provider dependency native participation control failed', result.stderr); self.assertEqual(result.stdout, '')


if __name__ == '__main__': unittest.main()

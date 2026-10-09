import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_update_effects as effects
import test_update_trigger_prefixes as prefixes
import test_update_triggers as triggers
import test_update_removals as removals


def entries(family='trigger', names=(b'glibc', b'kernel'), versions=(b'2:1.0~rc1-3.azl3', b'1.1'), masks=(12, 8)):
    identifiers = {'trigger': (1066, 1067, 1068), 'filetrigger': (5069, 5071, 5072),
                   'transfiletrigger': (5079, 5081, 5082)}[family]
    name, version, sense = identifiers
    return [(tag, kind, list(names) if tag == name else list(versions) if tag == version else
             [65536 | mask for mask in masks] if tag == sense else values)
            for tag, kind, values in triggers.trigger_entries(family, scripts=2, indexes=(1, 0))]


class ConditionDeclarationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.namespace = prefixes.library()

    def literal(self, version=b'', sense=65536, family='trigger', name='glibc'):
        return self.namespace['trigger_condition_literal'](family, name, version, sense)

    def test_six_declared_comparison_forms_preserve_exact_operator_and_evr(self):
        for mask, operator in ((0, None), (2, '<'), (4, '>'), (8, '='), (10, '<='), (12, '>=')):
            version = b'1.0' if mask else b''
            with self.subTest(mask=mask):
                value = self.literal(version, 65536 | mask)
                self.assertEqual((value['comparison_mask'], value['declared_operator'], value['evr']),
                                 (mask, operator, version.decode()))

    def test_epoch_and_release_omissions_remain_distinct_from_explicit_zero(self):
        for version, expected in ((b'1.0', (None, '1.0', None)), (b'0:1.0', ('0', '1.0', None)),
                                  (b'1.0-2', (None, '1.0', '2')), (b'7:1.0-2', ('7', '1.0', '2'))):
            with self.subTest(version=version):
                parts = self.literal(version, 65536 | 8)['evr_parts']
                self.assertEqual(tuple(parts[name] for name in ('epoch', 'version', 'release')), expected)

    def test_tilde_caret_and_zero_padded_version_segments_are_only_observed(self):
        value = self.literal(b'2:1.01~rc1^git-03.azl3', 65536 | 12)
        self.assertEqual(value['evr'], '2:1.01~rc1^git-03.azl3')
        self.assertEqual(value['evr_parts']['version'], '1.01~rc1^git')

    def test_uint32_epoch_bound_is_not_silently_truncated(self):
        self.assertEqual(self.literal(b'4294967295:1-1', 65536 | 8)['evr_parts']['epoch'], '4294967295')
        with self.assertRaisesRegex(ValueError, 'canonical declaration'):
            self.literal(b'4294967296:1-1', 65536 | 8)

    def test_noncanonical_epoch_and_missing_or_multiple_components_refuse(self):
        for version in (b'01:1', b'+1:1', b'-1:1', b':1', b'1:', b'1:-2', b'1:1-', b'1:1-2-3', b'1:2:3'):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'canonical declaration'):
                self.literal(version, 65536 | 8)

    def test_empty_evr_requires_no_comparison_and_nonempty_requires_one(self):
        self.assertIsNone(self.literal()['evr_parts'])
        for version, mask in ((b'', 8), (b'1', 0)):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'declaration disagree'):
                self.literal(version, 65536 | mask)

    def test_unsupported_combined_less_greater_masks_refuse(self):
        for mask in (6, 14):
            with self.subTest(mask=mask), self.assertRaisesRegex(ValueError, 'comparison mask'):
                self.literal(b'1', 65536 | mask)

    def test_unknown_noncomparison_bits_are_retained_without_policy_approval(self):
        sense = 65536 | 8 | 1 | 1 << 29
        value = self.literal(b'1', sense)
        self.assertEqual(value['declared_sense'], sense)
        self.assertEqual(value['uninterpreted_sense_bits'], 1 | 1 << 29)

    def test_boolean_negative_and_out_of_width_senses_refuse(self):
        for sense in (True, -1, 2**32):
            with self.subTest(sense=sense), self.assertRaisesRegex(ValueError, 'sense is unsupported'):
                self.literal(sense=sense)

    def test_both_file_families_require_empty_version_and_zero_comparison(self):
        for family in ('filetrigger', 'transfiletrigger'):
            self.assertEqual(self.literal(family=family, name='/usr/lib/')['evr'], '')
            for version, mask in ((b'1', 8), (b'1', 0), (b'', 8)):
                with self.subTest(family=family, version=version), self.assertRaisesRegex(ValueError, 'versioned file-trigger'):
                    self.literal(version, 65536 | mask, family, '/usr/lib/')

    def test_supported_package_names_and_256_byte_bound(self):
        for name in ('libstdc++', 'kernel-hwe', 'a' * 256): self.assertEqual(self.literal(name=name)['name'], name)
        with self.assertRaisesRegex(ValueError, 'package-name profile'): self.literal(name='a' * 257)

    def test_virtual_path_rich_macro_whitespace_and_unicode_names_defer(self):
        for name in ('', '/usr/bin/sh', '_hidden', 'libc.so.6()(64bit)', '(foo or bar)', '%{name}', 'foo bar', 'foo\nbar', 'glïbc'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'package-name profile'):
                self.literal(name=name)

    def test_1024_byte_evr_is_admitted_and_1025_deferred(self):
        self.assertEqual(self.literal(b'a' * 1024, 65536 | 8)['evr'], 'a' * 1024)
        with self.assertRaisesRegex(ValueError, 'exceeds its bound'): self.literal(b'a' * 1025, 65536 | 8)

    def test_control_macro_shell_and_unicode_evr_bytes_refuse_without_evaluation(self):
        for version in (b'1\n2', b'1\x002', b'%{version}', b'$(false)', b'1 2', '1\u2028x'.encode(), b'\xff'):
            with self.subTest(version=version), self.assertRaises((ValueError, UnicodeError)):
                self.literal(version, 65536 | 8)


class ConditionProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.namespace = prefixes.library()

    def project(self, values):
        material = effects.exported(values); audited = self.namespace['audit_header'](material)
        projected = self.namespace['trigger_condition_export'](material, audited)
        owner = {**audited, 'trigger_condition_bytes': projected}
        return material, owner, self.namespace['trigger_tags'](owner)

    def test_exact_name_and_version_positions_and_empty_versions_are_projected(self):
        _, owner, tags = self.project(entries(versions=(b'2:1-3', b''), masks=(12, 0)))
        self.assertEqual(owner['trigger_condition_bytes'], [{'tag': 1066, 'hex_values': [b'glibc'.hex(), b'kernel'.hex()]},
            {'tag': 1067, 'hex_values': [b'2:1-3'.hex(), '']}])
        self.assertEqual(self.namespace['trigger_condition_values'](owner, tags)[1067], [b'2:1-3', b''])

    def test_file_name_projection_remains_separate_and_bodies_are_not_collected(self):
        _, owner, _ = self.project(entries('filetrigger', (b'/usr/lib', b'/usr/lib/'), (b'', b''), (0, 0)))
        self.assertEqual([value['tag'] for value in owner['trigger_condition_bytes']], [5071])
        self.assertNotIn('opaque', json.dumps(owner)); self.assertNotIn('/usr/lib', json.dumps(owner))

    def test_raw_header_binding_is_enforced_by_the_reused_collector(self):
        material, owner, _ = self.project(entries()); owner['header_sha256'] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'audited header'): self.namespace['trigger_condition_export'](material, owner)

    def test_projection_missing_duplicate_foreign_and_boolean_tags_refuse(self):
        for change in ('missing', 'duplicate', 'foreign', 'boolean'):
            _, owner, tags = self.project(entries()); projected = owner['trigger_condition_bytes']
            if change == 'missing': projected.pop()
            elif change == 'duplicate': projected.append(copy.deepcopy(projected[0]))
            else: projected[0]['tag'] = 5079 if change == 'foreign' else True
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'projection is missing'):
                self.namespace['trigger_condition_values'](owner, tags)

    def test_count_hex_and_individual_digest_correspondence_are_required(self):
        for change in ('count', 'odd', 'uppercase', 'hash', 'large'):
            _, owner, tags = self.project(entries()); values = owner['trigger_condition_bytes'][0]['hex_values']
            if change == 'count': values.pop()
            else: values[0] = {'odd': '2f7', 'uppercase': '6A', 'hash': b'foreign'.hex(), 'large': '61' * 257}[change]
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.namespace['trigger_condition_values'](owner, tags)

    def test_array_hash_is_required_even_when_item_hashes_match_modified_bytes(self):
        _, owner, tags = self.project(entries()); row = tags[1067]
        row['sha256'] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'array differs'):
            self.namespace['trigger_condition_values'](owner, tags)


class ConditionProofTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof

    @classmethod
    def setUpClass(cls): cls.namespace = prefixes.library()

    def replace_owner(self, proof, values):
        material = effects.exported(values); audited = self.namespace['audit_header'](material)
        owner = proof['effects']['installed_script_owners'][0]
        owner.update(audited, file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited),
                     trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner}, proof['baseline'])
        return owner

    def observe(self, proof):
        return self.namespace['trigger_condition_observe'](self.namespace['trigger_observe'](proof))

    def test_all_three_families_bind_name_version_operator_and_original_indexes(self):
        for family in ('trigger', 'filetrigger', 'transfiletrigger'):
            proof = self.proof()
            source = entries() if family == 'trigger' else entries(family, (b'/usr/lib', b'/usr/lib/'), (b'', b''), (0, 0))
            self.replace_owner(proof, source)
            receipt = self.observe(proof)['trigger_condition_observation']
            conditions = receipt['owners'][0]['families'][0]['conditions']
            self.assertEqual([(value['condition_position'], value['script_index']) for value in conditions], [(0, 1), (1, 0)])
            self.assertEqual(receipt['conditions'], 2); self.assertTrue(receipt['declared_condition_strings_observed'])

    def test_complete_compact_owner_size_digest_and_full_baseline_are_bound(self):
        proof = self.proof(); self.replace_owner(proof, entries())
        receipt = self.observe(proof)['trigger_condition_observation']
        material = json.dumps(receipt['owners'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual(receipt['owners_bytes'], len(material)); self.assertEqual(receipt['owners_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(receipt['baseline_sha256'], proof['baseline']['sha256'])
        self.assertEqual(receipt['inventory_sha256'], proof['effects']['installed_versions']['entries_sha256'])

    def test_fifteen_authority_and_match_flags_remain_false(self):
        receipt = self.observe(self.proof())['trigger_condition_observation']
        for name in ('evr_comparisons_performed', 'conditions_evaluated', 'package_matches_observed', 'prefix_matches_observed',
                     'transaction_file_actions_observed', 'trigger_selection_complete', 'execution_order_complete',
                     'script_execution_plan_complete', 'installed_headers_authenticated', 'script_policy_satisfied',
                     'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready'):
            self.assertIs(receipt[name], False, name)

    def test_empty_batch_without_trigger_owners_withholds_string_observation(self):
        receipt = self.observe(self.proof(trigger=False, incoming=False))['trigger_condition_observation']
        self.assertEqual(receipt['conditions'], 0); self.assertFalse(receipt['declared_condition_strings_observed'])

    def test_no_stale_prefix_receipt_replaces_current_prefix_guard(self):
        proof = self.proof(); proof['file_trigger_prefix_observation'] = {'literal_prefixes_observed': True}
        proof['effects']['installed_script_owners'][0]['file_trigger_prefix_bytes'].clear()
        with self.assertRaisesRegex(ValueError, 'projection is missing'): self.observe(proof)

    def test_missing_incoming_condition_projection_cannot_borrow_installed_success(self):
        proof = self.proof(); del proof['effects']['incoming'][0]['trigger_condition_bytes']
        with self.assertRaises(KeyError): self.observe(proof)

    def test_removal_condition_projection_must_match_same_installed_owner(self):
        proof = self.proof(); owner = self.replace_owner(proof, entries())
        proof['effects']['removals'] = [{**copy.deepcopy(owner), 'classification': 'other-removal'}]
        proof['removals'] = [owner['nevra']]; self.observe(copy.deepcopy(proof))
        proof['effects']['removals'][0]['trigger_condition_bytes'][0]['hex_values'][0] = b'foreign'.hex()
        with self.assertRaisesRegex(ValueError, 'removal conditions differ'): self.observe(proof)

    def test_partial_bad_second_condition_withholds_entire_new_receipt(self):
        proof = self.proof(); self.replace_owner(proof, entries(versions=(b'1', b'01:2')))
        with self.assertRaisesRegex(ValueError, 'canonical declaration'): self.observe(proof)
        self.assertNotIn('trigger_condition_observation', proof)

    def test_aggregate_string_byte_bound_withholds_output_in_scaled_model(self):
        previous = self.namespace['TRIGGER_CONDITION_LIMIT']; self.namespace['TRIGGER_CONDITION_LIMIT'] = 1
        try:
            proof = self.proof()
            with self.assertRaisesRegex(ValueError, 'aggregate observation bound'): self.observe(proof)
            self.assertNotIn('trigger_condition_observation', proof)
        finally: self.namespace['TRIGGER_CONDITION_LIMIT'] = previous


class ConditionPrivateTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    setUp = triggers.TriggerPrivateInputTests.setUp
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_private_snapshot_binds_all_three_receipts_to_same_bytes(self):
        material = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation'):
            self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(self.path.read_bytes(), material)

    def test_stale_condition_receipt_cannot_replace_missing_raw_projection(self):
        proof = self.proof(); proof['trigger_condition_observation'] = {'declared_condition_strings_observed': True}
        del proof['effects']['installed_script_owners'][0]['trigger_condition_bytes']
        self.path.write_text(json.dumps(proof)); self.run_guard(expected=75)

    def test_versioned_file_condition_refuses_on_real_private_path_without_mutation(self):
        proof = self.proof(); material = effects.exported(entries('transfiletrigger', (b'/usr/lib', b'/usr/lib/'), (b'', b'1'), (0, 8)))
        owner = proof['effects']['installed_script_owners'][0]; audited = self.namespace['audit_header'](material)
        owner.update(audited, file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited),
                     trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner}, proof['baseline'])
        self.path.write_text(json.dumps(proof)); before = self.path.read_bytes()
        self.assertIn('versioned file-trigger', self.run_guard(expected=75).stderr)
        self.assertEqual(self.path.read_bytes(), before)


class ConditionPipelineTests(unittest.TestCase):
    command = effects.UpdateEffectsTests.command
    configure = effects.UpdateEffectsTests.configure
    calls = effects.UpdateEffectsTests.calls
    setUp = effects.UpdateEffectsTests.setUp
    header = effects.UpdateEffectsTests.header
    prepare = effects.UpdateEffectsTests.prepare
    native_calls = effects.UpdateEffectsTests.native_calls

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-condition-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.library = Path(temporary.name) / 'librpm-condition-model.so'
        source = effects.LIBRARY.replace('uint32_t count=setting("trigger_missing_priority")?7:8;',
            'uint32_t count=setting("trigger_missing_priority")||setting("condition_ordinary")?7:8;\n'
            '    if(setting("condition_ordinary")) { uint32_t ordinary[]={1065,1092,5027,1066,1067,1068,1069,0};memcpy(tags,ordinary,sizeof(tags)); }')
        source = source.replace('NULL,"/usr/lib", "",NULL,NULL,NULL',
            'NULL,setting("condition_ordinary")?"userland":"/usr/lib",setting("condition_bad_epoch")?"01:1":setting("condition_ordinary")?"2:1.0~rc1-3.azl3":setting("condition_versioned_file")?"1":"",NULL,NULL,NULL')
        source = source.replace('0,0,0,0,0,65536,setting("trigger_bad_index")',
            '0,0,0,0,0,65536|(setting("condition_ordinary")?12:setting("condition_versioned_file")?8:0),setting("trigger_bad_index")')
        assert source != effects.LIBRARY
        from test_update_header_inputs import header_model_source
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=header_model_source(source + (effects.SOURCE.parent / 'Updates.Tests/rpm_version_model.c').read_text()
                                    + (effects.SOURCE.parent / 'Updates.Tests/rpm_range_model.c').read_text()),
                       text=True, capture_output=True, check=True)

    def shell(self, body='s4_check_update_effects', expected=0, timeout=90):
        program = triggers.emitted()
        self.assertEqual(program.count('C.CDLL("librpm.so.9",'), 5)
        delivered = program.replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        override = "s4_update_trigger_inputs_program() { cat <<'S4_RANGE_MODEL'\n" + delivered + '\nS4_RANGE_MODEL\n}\n'
        return effects.UpdateEffectsTests.shell(self, override + body, expected, timeout)

    def test_current_test_binds_package_evr_declaration_to_same_header_and_snapshot(self):
        self.prepare(condition_ordinary=True, userland_removal=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout); receipt = proof['trigger_condition_observation']
        self.assertEqual(receipt['conditions'], 1)
        record = receipt['owners'][0]['families'][0]['conditions'][0]
        self.assertEqual((record['name'], record['evr'], record['declared_operator']), ('userland', '2:1.0~rc1-3.azl3', '>='))
        self.assertEqual(receipt['owners'][0]['header_sha256'], proof['effects']['installed_script_owners'][0]['header_sha256'])
        source = copy.deepcopy(proof)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation', 'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation', 'header_input_observation', 'header_match_observation', 'trigger_first_observation', 'header_iteration_observation', 'trigger_count_observation', 'trigger_argument_observation', 'trigger_iterator_observation', 'trigger_walk_observation', 'transaction_element_observation', 'psm_goal_observation', 'psm_input_observation', 'psm_route_observation', 'psm_failure_observation', 'psm_verification_observation'): source.pop(name)
        self.assertEqual(receipt['input_sha256'], hashlib.sha256((json.dumps(source, sort_keys=True) + '\n').encode()).hexdigest())
        self.assertFalse(receipt['conditions_evaluated']); self.assertFalse(proof['installation_authorized'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_bad_epoch_and_versioned_file_refuse_after_current_test_without_output(self):
        records = []
        for scenario, reason in (({'condition_ordinary': True, 'condition_bad_epoch': True}, 'canonical declaration profile'),
                                 ({'condition_versioned_file': True}, 'versioned file-trigger')):
            with self.subTest(scenario=scenario):
                self.prepare(**scenario); pointer = (self.root / 'state/updates/current.json').read_bytes()
                result = self.shell(expected=75); self.assertIn(reason, result.stderr); self.assertIn('run 1', self.native_calls())
                self.assertEqual(result.stdout, ''); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
                records.append({'scenario': scenario, 'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr,
                    'native_test_seen': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
                    'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
                    'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False})
        self.record = {'refusals': records}

    def test_invalid_condition_keeps_existing_effects_component_pending(self):
        self.prepare(condition_ordinary=True, condition_bad_epoch=True)
        self.shell('s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())


if __name__ == '__main__': unittest.main()

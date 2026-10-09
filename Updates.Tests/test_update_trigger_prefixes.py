import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import test_update_effects as effects
import test_update_triggers as triggers
import test_update_removals as removals


def library():
    namespace = {'__name__': 'prefix_fixture_library'}
    exec(compile(triggers.emitted(), '<emitted-prefix-library>', 'exec'), namespace)
    return namespace


def prefix_entries(family='transfiletrigger', prefixes=(b'/usr/lib', b'/usr/lib/'), indexes=(0, 1)):
    tag = 5069 if family == 'filetrigger' else 5079
    entries = triggers.trigger_entries(family, scripts=2, indexes=indexes)
    return [(number, kind, list(prefixes) if number == tag else values) for number, kind, values in entries]


class PrefixExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.namespace = library()

    def project(self, entries):
        material = effects.exported(entries)
        audited = self.namespace['audit_header'](material)
        return material, audited, self.namespace['file_trigger_export'](material, audited)

    def test_both_file_families_project_exact_bytes_in_source_order(self):
        for family, tag in (('filetrigger', 5069), ('transfiletrigger', 5079)):
            with self.subTest(family=family):
                _, audited, rows = self.project(prefix_entries(family))
                self.assertEqual(rows, [{'tag': tag, 'hex_values': [b'/usr/lib'.hex(), b'/usr/lib/'.hex()]}])
                source = next(entry for entry in audited['tags'] if entry['tag'] == tag)
                self.assertEqual(source['values'][0]['sha256'], hashlib.sha256(b'/usr/lib').hexdigest())

    def test_package_conditions_and_all_script_bodies_remain_opaque(self):
        entries = triggers.trigger_entries('trigger')
        _, audited, rows = self.project(entries)
        self.assertEqual(rows, [])
        self.assertNotIn('opaque', json.dumps(audited)); self.assertNotIn('/declared/prefix', json.dumps(audited))

    def test_file_body_and_version_bytes_are_not_added_to_prefix_projection(self):
        entries = [(tag, kind, [b'\xff$(false)'] * len(values) if tag in (5076, 5081) else values)
                   for tag, kind, values in prefix_entries()]
        _, audited, rows = self.project(entries)
        self.assertNotIn('false', json.dumps(audited)); self.assertNotIn('false', json.dumps(rows))

    def test_export_hash_and_size_bind_the_same_material(self):
        material, audited, _ = self.project(prefix_entries())
        for field, value in (('header_bytes', len(material) + 1), ('header_sha256', 'a' * 64)):
            changed = copy.deepcopy(audited); changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'audited header'):
                self.namespace['file_trigger_export'](material, changed)

    def test_each_item_and_complete_encoded_array_digest_are_required(self):
        material, audited, _ = self.project(prefix_entries())
        for field in ('item', 'array', 'bytes'):
            changed = copy.deepcopy(audited)
            row = next(entry for entry in changed['tags'] if entry['tag'] == 5079)
            if field == 'item': row['values'][0]['sha256'] = 'a' * 64
            elif field == 'array': row['sha256'] = 'a' * 64
            else: row['bytes'] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'differ'):
                self.namespace['file_trigger_export'](material, changed)

    def test_projection_checks_type_count_and_missing_known_tag(self):
        material, audited, _ = self.project(prefix_entries())
        for change in ('type', 'count', 'missing'):
            altered = copy.deepcopy(audited)
            row = next(entry for entry in altered['tags'] if entry['tag'] == 5079)
            if change == 'missing': altered['tags'].remove(row)
            else: row[change] = 4 if change == 'type' else 1
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'tag is inconsistent'):
                self.namespace['file_trigger_export'](material, altered)

    def test_4096_byte_prefix_is_retained_but_4097_refuses(self):
        raw = b'/' + b'a' * 4095
        self.assertEqual(self.project(prefix_entries(prefixes=(raw, raw)))[2][0]['hex_values'][0], raw.hex())
        with self.assertRaisesRegex(ValueError, '4096-byte bound'):
            self.project(prefix_entries(prefixes=(raw + b'a', raw)))

    def test_raw_non_ascii_bytes_survive_projection_until_literal_admission(self):
        raw = b'/usr/\xff'
        self.assertEqual(self.project(prefix_entries(prefixes=(raw, b'/usr/lib')))[2][0]['hex_values'][0], raw.hex())
        with self.assertRaises(UnicodeError): self.namespace['file_trigger_literal'](raw)

    def test_root_trailing_slash_and_exact_prefix_bytes_are_preserved(self):
        for raw in (b'/', b'/usr/lib', b'/usr/lib/', b'/.cache/lib-1.2_+@,:='):
            with self.subTest(raw=raw): self.assertEqual(self.namespace['file_trigger_literal'](raw), raw.decode('ascii'))

    def test_relative_repeated_dot_and_dotdot_components_refuse_without_normalization(self):
        for raw in (b'usr/lib', b'//usr/lib', b'/usr//lib', b'/usr/./lib', b'/usr/../lib', b'/usr/lib//', b'/./', b'/../'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'literal path profile'):
                self.namespace['file_trigger_literal'](raw)

    def test_controls_globs_macros_shell_forms_and_unicode_refuse_as_unsupported_literals(self):
        for raw in (b'/usr/\nlib', b'/usr/\0lib', b'/usr/ lib', b'/usr/*', b'/usr/?', b'/usr/[x]',
                    b'/usr/%{macro}', b'/usr/$(false)', b'/usr/\\lib', '/usr/é'.encode(), '/usr/\u2028lib'.encode()):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                self.namespace['file_trigger_literal'](raw)

    def test_no_selected_name_tags_yield_an_explicit_empty_projection(self):
        self.assertEqual(self.project([(1000, 6, [b'fixture'])])[2], [])


class PrefixProofTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof

    @classmethod
    def setUpClass(cls): cls.namespace = library()

    def replace_owner(self, proof, entries):
        material = effects.exported(entries); audited = self.namespace['audit_header'](material)
        owner = proof['effects']['installed_script_owners'][0]
        owner.update(audited, file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner}, proof['baseline'])
        return owner

    def observe(self, proof):
        return self.namespace['file_trigger_prefix_observe'](self.namespace['trigger_observe'](proof))

    def test_source_positions_indexes_phases_and_trailing_slash_are_bound(self):
        proof = self.proof(); self.replace_owner(proof, prefix_entries(indexes=(1, 0)))
        result = self.observe(proof)['file_trigger_prefix_observation']
        conditions = result['owners'][0]['families'][0]['conditions']
        self.assertEqual([(v['condition_position'], v['script_index'], v['prefix']) for v in conditions],
                         [(0, 1, '/usr/lib'), (1, 0, '/usr/lib/')])
        self.assertEqual([v['declared_sense'] for v in conditions], [65536, 65536])
        self.assertEqual(result['prefixes'], 2); self.assertTrue(result['literal_prefixes_observed'])

    def test_complete_compact_owner_commitment_matches_delivered_records(self):
        receipt = self.observe(self.proof())['file_trigger_prefix_observation']
        material = json.dumps(receipt['owners'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual(receipt['owners_bytes'], len(material))
        self.assertEqual(receipt['owners_sha256'], hashlib.sha256(material).hexdigest())

    def test_all_new_authority_and_selection_flags_remain_false(self):
        result = self.observe(self.proof())['file_trigger_prefix_observation']
        for name in ('all_condition_text_available', 'conditions_evaluated', 'prefix_matches_observed',
                     'transaction_file_actions_observed', 'trigger_selection_complete', 'execution_order_complete',
                     'script_execution_plan_complete', 'installed_headers_authenticated', 'script_policy_satisfied',
                     'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready'):
            self.assertIs(result[name], False, name)

    def test_empty_and_ordinary_only_batches_withhold_literal_observation(self):
        proof = self.proof(trigger=False, incoming=False)
        result = self.observe(proof)['file_trigger_prefix_observation']
        self.assertEqual(result['prefixes'], 0); self.assertFalse(result['literal_prefixes_observed'])
        proof = self.proof(); self.replace_owner(proof, triggers.trigger_entries('trigger', scripts=1, indexes=(0,)))
        self.assertFalse(self.observe(proof)['file_trigger_prefix_observation']['literal_prefixes_observed'])

    def test_missing_duplicate_and_foreign_projection_records_refuse(self):
        for change in ('missing', 'duplicate', 'foreign', 'boolean'):
            proof = self.proof(); rows = proof['effects']['installed_script_owners'][0]['file_trigger_prefix_bytes']
            if change == 'missing': rows.clear()
            elif change == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            else: rows[0]['tag'] = 1066 if change == 'foreign' else True
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'projection is missing'):
                self.observe(proof)

    def test_missing_incoming_projection_is_not_satisfied_by_installed_success(self):
        proof = self.proof(); del proof['effects']['incoming'][0]['file_trigger_prefix_bytes']
        with self.assertRaises(KeyError): self.observe(proof)

    def test_uppercase_odd_invalid_and_oversized_hex_refuse_before_decoding(self):
        for value in ('2F757372', '2f7', 'zz', ' 2f', '2f' * 4097, ''):
            proof = self.proof(); proof['effects']['installed_script_owners'][0]['file_trigger_prefix_bytes'][0]['hex_values'] = [value]
            with self.subTest(value=value[:20]), self.assertRaisesRegex(ValueError, 'byte encoding'):
                self.observe(proof)

    def test_count_and_source_digest_mismatch_refuse(self):
        for change in ('count', 'bytes'):
            proof = self.proof(); values = proof['effects']['installed_script_owners'][0]['file_trigger_prefix_bytes'][0]['hex_values']
            if change == 'count': values.append(values[0])
            else: values[0] = b'/unrelated/path'.hex()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'differ'):
                self.observe(proof)

    def test_duplicate_prefixes_preserve_each_condition_reference(self):
        proof = self.proof(); self.replace_owner(proof, prefix_entries(prefixes=(b'/usr/lib', b'/usr/lib')))
        receipt = self.observe(proof)['file_trigger_prefix_observation']
        self.assertEqual(receipt['prefixes'], 2)
        self.assertEqual([v['condition_position'] for v in receipt['owners'][0]['families'][0]['conditions']], [0, 1])

    def test_removal_projection_must_equal_the_same_installed_instance(self):
        proof = self.proof(); owner = proof['effects']['installed_script_owners'][0]
        proof['effects']['removals'] = [{**copy.deepcopy(owner), 'classification': 'other-removal'}]
        proof['removals'] = [owner['nevra']]
        self.observe(copy.deepcopy(proof))
        proof['effects']['removals'][0]['file_trigger_prefix_bytes'][0]['hex_values'][0] = b'/wrong'.hex()
        with self.assertRaisesRegex(ValueError, 'removal prefix bytes'): self.observe(proof)

    def test_aggregate_prefix_byte_bound_withholds_partial_result_in_scaled_model(self):
        saved = self.namespace['FILE_TRIGGER_PREFIX_LIMIT']
        self.namespace['FILE_TRIGGER_PREFIX_LIMIT'] = 1
        try:
            proof = self.proof()
            with self.assertRaisesRegex(ValueError, 'aggregate observation bound'): self.observe(proof)
            self.assertNotIn('file_trigger_prefix_observation', proof)
        finally: self.namespace['FILE_TRIGGER_PREFIX_LIMIT'] = saved

    def test_package_conditions_and_version_senses_are_not_interpreted(self):
        proof = self.proof()
        entries = [(tag, kind, [b'\xffunknown'] * len(values) if tag == 5081 else
                    [65536 | 2 | 1 << 29] * len(values) if tag == 5082 else values) for tag, kind, values in prefix_entries()]
        self.replace_owner(proof, entries)
        result = self.observe(proof)['file_trigger_prefix_observation']
        self.assertEqual(result['owners'][0]['families'][0]['conditions'][0]['declared_sense'], 65536 | 2 | 1 << 29)
        self.assertFalse(result['conditions_evaluated'])


class PrefixPrivateTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    setUp = triggers.TriggerPrivateInputTests.setUp
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_private_guard_binds_both_receipts_to_same_snapshot(self):
        material = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation'):
            self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(self.path.read_bytes(), material)

    def test_stale_correspondence_cannot_replace_missing_prefix_bytes(self):
        proof = self.proof(); proof['trigger_input_observation'] = {'declared_arrays_correspond': True}
        del proof['effects']['installed_script_owners'][0]['file_trigger_prefix_bytes']
        self.path.write_text(json.dumps(proof)); self.run_guard(expected=75)

    def test_valid_first_owner_then_unsupported_prefix_publishes_no_json(self):
        proof = self.proof(); owner = proof['effects']['installed_script_owners'][0]
        material = effects.exported(prefix_entries(prefixes=(b'/usr/lib', b'/usr/../bad')))
        audited = self.namespace['audit_header'](material)
        owner.update(audited, file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited))
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner}, proof['baseline'])
        self.path.write_text(json.dumps(proof)); before = self.path.read_bytes()
        self.assertIn('literal path profile', self.run_guard(expected=75).stderr)
        self.assertEqual(self.path.read_bytes(), before)


class PrefixPipelineTests(unittest.TestCase):
    command = effects.UpdateEffectsTests.command
    configure = effects.UpdateEffectsTests.configure
    calls = effects.UpdateEffectsTests.calls
    setUp = effects.UpdateEffectsTests.setUp
    header = effects.UpdateEffectsTests.header
    prepare = effects.UpdateEffectsTests.prepare
    native_calls = effects.UpdateEffectsTests.native_calls

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-prefix-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.library = Path(temporary.name) / 'librpm-prefix-model.so'
        source = effects.LIBRARY.replace('NULL,"/usr/lib", "",NULL',
            'NULL,setting("prefix_relative")?"usr/lib":"/usr/lib/", "",NULL')
        assert source != effects.LIBRARY
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=source + (effects.SOURCE.parent / 'Updates.Tests/rpm_version_model.c').read_text(),
                       text=True, capture_output=True, check=True)

    def shell(self, body='s4_check_update_effects', expected=0, timeout=90):
        if body == 's4_check_update_removals':
            return removals.UpdateRemovalIntegrationTests.shell(self, body, expected, timeout)
        return effects.UpdateEffectsTests.shell(self, body, expected, timeout)

    def test_current_test_projects_same_header_prefix_and_preserves_retained_batch(self):
        self.prepare(userland_removal=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout); receipt = proof['file_trigger_prefix_observation']
        self.assertEqual(receipt['prefixes'], 1)
        owner = receipt['owners'][0]; self.assertEqual(owner['instance'], 1)
        self.assertEqual(owner['families'][0]['conditions'][0]['prefix'], '/usr/lib/')
        self.assertEqual(owner['header_sha256'], proof['effects']['installed_script_owners'][0]['header_sha256'])
        source = copy.deepcopy(proof); source.pop('trigger_input_observation'); source.pop('file_trigger_prefix_observation'); source.pop('trigger_condition_observation');source.pop('trigger_range_observation');source.pop('provides_observation');source.pop('provider_match_observation');source.pop('trigger_source_observation');source.pop('header_input_observation');source.pop('header_match_observation');source.pop('trigger_first_observation');source.pop('header_iteration_observation');source.pop('trigger_count_observation')
        self.assertEqual(receipt['input_sha256'], hashlib.sha256((json.dumps(source, sort_keys=True) + '\n').encode()).hexdigest())
        self.assertFalse(receipt['trigger_selection_complete']); self.assertFalse(proof['installation_authorized'])
        self.assertIn('run 1', self.native_calls())
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_unsupported_literal_refuses_after_current_test_without_output(self):
        self.prepare(prefix_relative=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell(expected=75)
        self.assertIn('file-trigger prefix is outside the literal path profile', result.stderr)
        self.assertIn('run 1', self.native_calls()); self.assertEqual(result.stdout, '')
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_unsupported_prefix_keeps_existing_effects_component_pending(self):
        self.prepare(prefix_relative=True); self.shell('s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())

    def test_removal_diagnostic_bypasses_literal_projection_and_guard(self):
        self.prepare(prefix_relative=True, userland_removal=True)
        proof = json.loads(self.shell('s4_check_update_removals').stdout)
        self.assertNotIn('file_trigger_prefix_observation', proof)
        self.assertNotIn('file_trigger_prefix_bytes', proof['effects']['installed_script_owners'][0])
        self.assertFalse(proof['installation_authorized'])


if __name__ == '__main__': unittest.main()

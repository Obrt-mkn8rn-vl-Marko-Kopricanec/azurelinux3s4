import copy
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

import test_update_effects as effects
import test_update_trigger_prefixes as prefixes
import test_update_triggers as triggers
import test_update_trigger_conditions as conditions
import test_update_interpreters as interpreters
import test_update_removals as removals


def entries(names=(b'userland', b'libc.so.6()(64bit)'), versions=(b'1-1', b''), flags=(8, 0)):
    return [(1047, 8, list(names)), (1112, 4, list(flags)), (1113, 8, list(versions))]


class ProvidesDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.namespace = prefixes.library()

    def project(self, values):
        material = effects.exported(values)
        return self.namespace['provides_export'](material, self.namespace['audit_header'](material))

    def raw(self, material):
        return self.namespace['provides_export'](material, {
            'header_bytes': len(material), 'header_sha256': hashlib.sha256(material).hexdigest()})

    def test_exact_bytes_full_flags_empty_evr_and_positions_are_preserved(self):
        result = self.namespace['provides_records'](self.project(entries(flags=(8, 2**32 - 1))))
        self.assertEqual(result, [{'position': 0, 'name_hex': b'userland'.hex(), 'evr_hex': b'1-1'.hex(), 'declared_flags': 8},
            {'position': 1, 'name_hex': b'libc.so.6()(64bit)'.hex(), 'evr_hex': '', 'declared_flags': 2**32 - 1}])

    def test_duplicate_names_and_arbitrary_non_nul_bytes_are_not_normalized_or_evaluated(self):
        names = (b'%{macro}\xff$(false)', b'%{macro}\xff$(false)')
        result = self.namespace['provides_records'](self.project(entries(names, (b'01:opaque', b'\xff'), (0, 14))))
        self.assertEqual([bytes.fromhex(row['name_hex']) for row in result], list(names))
        self.assertEqual([row['position'] for row in result], [0, 1])
        self.assertEqual([row['declared_flags'] for row in result], [0, 14])

    def test_physical_tag_order_is_sorted_but_value_order_is_retained(self):
        result = self.project(list(reversed(entries())))
        self.assertEqual([row['tag'] for row in result['tags']], [1047, 1112, 1113])
        self.assertEqual(result['tags'][0]['values'], [b'userland'.hex(), b'libc.so.6()(64bit)'.hex()])

    def test_absence_is_explicit_and_unrelated_effect_tags_are_unchanged(self):
        values = [(1023, 6, [b'opaque script'])]
        material = effects.exported(values); old = self.namespace['audit_header'](material)
        self.assertEqual(self.project(values), {'schema': 1, 'tags': []})
        self.assertEqual(old, self.namespace['audit_header'](material))
        self.assertEqual(len(self.namespace['EFFECT_TAGS']), 44)

    def test_same_export_length_and_hash_binding_precede_projection(self):
        material = effects.exported(entries()); audited = self.namespace['audit_header'](material)
        for field, value in (('header_bytes', len(material) + 1), ('header_sha256', 'a' * 64)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'audited header'):
                self.namespace['provides_export'](material, {**audited, field: value})

    def test_each_partial_array_set_refuses_instead_of_inventing_flags_or_versions(self):
        values = entries()
        for keep in ((0,), (1,), (2,), (0, 1), (0, 2), (1, 2)):
            with self.subTest(keep=keep), self.assertRaisesRegex(ValueError, 'incomplete arrays'):
                self.project([values[index] for index in keep])

    def test_duplicate_known_tags_wrong_types_and_zero_or_excessive_counts_refuse(self):
        for values in (entries() + [entries()[0]], [(1047, 6, [b'userland']), *entries()[1:]],
                       [(1047, 8, []), *entries()[1:]], entries((b'x',) * 4097, (b'',) * 4097, (0,) * 4097)):
            with self.subTest(values=values[:1]), self.assertRaisesRegex(ValueError, 'type/count/identity'):
                self.project(values)

    def test_complete_array_counts_must_correspond(self):
        with self.assertRaisesRegex(ValueError, 'counts do not correspond'):
            self.project(entries(versions=(b'1',)))

    def test_empty_name_string_bounds_and_final_nul_are_enforced(self):
        accepted = self.project(entries((b'x' * 4096,), (b'v' * 1024,), (0,)))
        self.assertEqual(accepted['tags'][0]['count'], 1)
        for values in (entries((b'',), (b'',), (0,)), entries((b'x' * 4097,), (b'',), (0,)),
                       entries((b'x',), (b'v' * 1025,), (0,))):
            with self.subTest(values=values[0][2][0][:8]), self.assertRaisesRegex(ValueError, 'string'):
                self.project(values)
        raw = bytearray(effects.exported(entries())); raw[-1] = 120
        with self.assertRaisesRegex(ValueError, 'unterminated'): self.raw(raw)

    def test_integer_alignment_and_physical_header_bounds_refuse(self):
        material = effects.exported(entries())
        for offset in (1, len(material)):
            changed = bytearray(material); struct.pack_into('>I', changed, 8 + 16 + 8, offset)
            with self.subTest(offset=offset), self.assertRaises(ValueError): self.raw(changed)
        changed = bytearray(material); struct.pack_into('>I', changed, 8 + 16 + 12, 4096)
        with self.assertRaisesRegex(ValueError, 'integer array'): self.raw(changed)
        for changed in (material[:7], material[:-1], struct.pack('>II', 65537, 0)):
            with self.subTest(size=len(changed)), self.assertRaises(ValueError): self.raw(changed)

    def test_exact_4096_records_are_admitted_with_independent_encoded_array_hashes(self):
        projected = self.project(entries((b'x',) * 4096, (b'',) * 4096, (0,) * 4096))
        self.assertEqual(len(self.namespace['provides_records'](projected)), 4096)
        self.assertEqual(projected['tags'][1]['sha256'], hashlib.sha256(b'\0' * (4 * 4096)).hexdigest())


class ProvidesProofTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof

    @classmethod
    def setUpClass(cls): cls.namespace = prefixes.library()

    def make_proof(self):
        proof = self.proof()
        owner = proof['effects']['installed_script_owners'][0]
        material = effects.exported(triggers.trigger_entries(scripts=1, indexes=(0,)) + entries())
        audited = self.namespace['audit_header'](material)
        owner.update(audited, provides=self.namespace['provides_export'](material, audited),
            file_trigger_prefix_bytes=self.namespace['file_trigger_export'](material, audited),
            trigger_condition_bytes=self.namespace['trigger_condition_export'](material, audited))
        material = effects.exported([(1000, 6, [b'gpg-pubkey'])])
        audited = self.namespace['audit_header'](material)
        other = {'instance': 2, 'name': 'gpg-pubkey', 'nevra': 'gpg-pubkey-abc-def.(none)', **audited,
                 'provides': self.namespace['provides_export'](material, audited)}
        proof['baseline'] = {'headers': 2, 'sha256': hashlib.sha256(json.dumps(
            [(row['instance'], row['header_sha256']) for row in (owner, other)], separators=(',', ':')).encode()).hexdigest()}
        fields = (*self.namespace['INSTALLED_VERSION_FIELDS'], 'provides')
        proof['effects']['installed_provides'] = [{field: row[field] for field in fields} for row in (owner, other)]
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: owner, 2: other}, proof['baseline'])
        proof['effects']['installed_headers_observed'] = 2
        return proof

    def observe(self, proof):
        return self.namespace['provides_observe'](self.namespace['trigger_observe'](proof))

    def test_full_inventory_includes_scriptless_key_header_and_incoming_snapshot(self):
        proof = self.make_proof(); receipt = self.observe(proof)['provides_observation']
        self.assertEqual((receipt['installed_headers'], receipt['incoming_headers'], receipt['provides']), (2, 1, 2))
        self.assertEqual([owner.get('instance', owner.get('file')) for owner in receipt['owners']], [1, 2, 'packages/0.rpm'])
        self.assertEqual(receipt['owners'][1]['provides'], [])
        self.assertTrue(receipt['complete_observed_installed_projection'])
        self.assertEqual(receipt['owners'][0]['header_sha256'], proof['effects']['installed_versions']['entries'][0]['header_sha256'])

    def test_complete_compact_owner_declaration_and_baseline_commitments_reconcile(self):
        proof = self.make_proof(); receipt = self.observe(proof)['provides_observation']
        material = json.dumps(receipt['owners'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((receipt['owners_bytes'], receipt['owners_sha256']), (len(material), hashlib.sha256(material).hexdigest()))
        self.assertEqual(receipt['baseline_sha256'], proof['baseline']['sha256'])
        self.assertEqual(receipt['inventory_sha256'], proof['effects']['installed_versions']['entries_sha256'])

    def test_missing_duplicate_reordered_and_foreign_installed_rows_refuse(self):
        for change in ('missing', 'duplicate', 'order', 'instance', 'header', 'boolean'):
            proof = self.make_proof(); rows = proof['effects']['installed_provides']
            if change == 'missing': rows.pop()
            elif change == 'duplicate': rows[1] = copy.deepcopy(rows[0])
            elif change == 'order': rows.reverse()
            elif change == 'instance': rows[1]['instance'] = 3
            elif change == 'header': rows[1]['header_sha256'] = 'b' * 64
            else: rows[0]['instance'] = True
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'complete current inventory'):
                self.observe(proof)

    def test_unknown_fields_and_missing_or_boolean_projection_schema_refuse(self):
        for change in ('extra', 'schema', 'missing'):
            proof = self.make_proof(); row = proof['effects']['installed_provides'][1]
            if change == 'extra': row['extra'] = 0
            elif change == 'schema': row['provides']['schema'] = True
            else: del row['provides']
            with self.subTest(change=change), self.assertRaises(ValueError): self.observe(proof)

    def test_removal_must_reuse_exact_same_installed_declarations(self):
        proof = self.make_proof(); removed = copy.deepcopy(proof['effects']['installed_script_owners'][0])
        proof['effects']['removals'] = [{**removed, 'classification': 'other-removal'}]; proof['removals'] = [removed['nevra']]
        self.observe(copy.deepcopy(proof))
        proof['effects']['removals'][0]['provides']['tags'][1]['values'][0] = 0
        with self.assertRaisesRegex(ValueError, 'script/removal projection'): self.observe(proof)

    def test_missing_incoming_declarations_cannot_borrow_installed_or_stale_success(self):
        proof = self.make_proof(); proof['provides_observation'] = {'declared_provides_observed': True}
        del proof['effects']['incoming'][0]['provides']
        with self.assertRaises(KeyError): self.observe(proof)

    def test_tag_order_integer_types_hex_nul_and_array_hash_controls_refuse(self):
        for change in ('order', 'boolean', 'flags', 'upper', 'odd', 'nul', 'hash', 'bytes'):
            projected = self.make_proof()['effects']['installed_provides'][0]['provides']; tags = projected['tags']
            if change == 'order': tags.reverse()
            elif change == 'boolean': tags[0]['count'] = True
            elif change == 'flags': tags[1]['values'][0] = True
            elif change == 'upper': tags[0]['values'][0] = 'AB'
            elif change == 'odd': tags[0]['values'][0] = 'a'
            elif change == 'nul': tags[0]['values'][0] = '00'
            elif change == 'hash': tags[0]['sha256'] = 'b' * 64
            else: tags[0]['bytes'] += 1
            with self.subTest(change=change), self.assertRaises(ValueError): self.namespace['provides_records'](projected)

    def test_zero_declarations_do_not_invent_presence_or_provider_matches(self):
        receipt = self.observe(self.proof(trigger=False, incoming=False))['provides_observation']
        self.assertEqual(receipt['provides'], 0); self.assertFalse(receipt['declared_provides_observed'])
        self.assertTrue(receipt['complete_observed_installed_projection'])
        self.assertFalse(receipt['package_trigger_matches_observed'])

    def test_all_fifteen_authority_flags_remain_false(self):
        receipt = self.observe(self.make_proof())['provides_observation']
        for name in ('dependency_names_interpreted', 'provided_evr_ranges_compared', 'package_trigger_matches_observed',
            'transaction_temporal_sources_selected', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'installed_headers_authenticated', 'native_library_identity_authenticated',
            'script_policy_satisfied', 'removal_policy_satisfied', 'rollback_policy_satisfied',
            'installation_authorized', 'scripts_executed', 'server_ready'):
            self.assertIs(receipt[name], False, name)

    def test_record_and_byte_aggregate_bounds_withhold_new_receipt_in_scaled_models(self):
        for constant in ('PROVIDES_RECORD_LIMIT', 'PROVIDES_BYTES_LIMIT'):
            previous = self.namespace[constant]; self.namespace[constant] = 1
            try:
                proof = self.make_proof()
                with self.assertRaisesRegex(ValueError, 'aggregate observation bound'): self.observe(proof)
                self.assertNotIn('provides_observation', proof)
            finally: self.namespace[constant] = previous


class ProvidesPrivateTests(unittest.TestCase):
    proof = triggers.TriggerProofTests.proof
    setUp = triggers.TriggerPrivateInputTests.setUp
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_snapshot_binds_all_five_receipts_and_is_preserved(self):
        material = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation',
                     'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation', 'header_input_observation', 'header_match_observation', 'trigger_first_observation', 'header_iteration_observation', 'trigger_count_observation', 'trigger_argument_observation', 'trigger_iterator_observation', 'trigger_walk_observation', 'transaction_element_observation', 'psm_goal_observation', 'psm_input_observation', 'psm_route_observation', 'psm_failure_observation'):
            self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(self.path.read_bytes(), material)

    def test_missing_current_projection_refuses_despite_stale_positive_receipt(self):
        proof = self.proof(); del proof['effects']['installed_provides']
        proof['provides_observation'] = {'declared_provides_observed': True}
        self.path.write_text(json.dumps(proof)); material = self.path.read_bytes()
        self.assertIn('installed_provides', self.run_guard(expected=75).stderr)
        self.assertEqual(self.path.read_bytes(), material)


PROVIDES_MODEL = r'''
void *headerExport(void *h,unsigned *size) {
    unsigned oldsize=0; unsigned char *old=fixtureProvidesOriginalExport(h,&oldsize);
    uint32_t n,ds; memcpy(&n,old,4);n=ntohl(n);memcpy(&ds,old+4,4);ds=ntohl(ds);
    unsigned added=setting("provides_partial")?2:3;
    const char *names[]={incoming(h)?"userland":"virtual-capability","libc.so.6()(64bit)"};
    const char *versions[]={incoming(h)?"1-1":"9:7-3",""};
    unsigned lengths[3]={strlen(names[0])+1+strlen(names[1])+1,8,strlen(versions[0])+1+1};
    unsigned offsets[3]={ds,0,0};offsets[1]=(ds+lengths[0]+3)&~3U;offsets[2]=offsets[1]+lengths[1];
    unsigned newds=added==2?offsets[2]:offsets[2]+lengths[2];
    *size=8+16*(n+added)+newds;unsigned char *result=calloc(1,*size);uint32_t v=htonl(n+added);
    memcpy(result,&v,4);v=htonl(newds);memcpy(result+4,&v,4);memcpy(result+8,old+8,16*n);
    memcpy(result+8+16*(n+added),old+8+16*n,ds);
    uint32_t tags[]={1047,1112,1113},kinds[]={8,4,8};
    for(unsigned i=0;i<added;i++) {
        uint32_t row[]={tags[i],kinds[i],offsets[i],2};
        for(unsigned j=0;j<4;j++){v=htonl(row[j]);memcpy(result+8+16*(n+i)+4*j,&v,4);}
    }
    unsigned char *data=result+8+16*(n+added);
    memcpy(data+offsets[0],names[0],strlen(names[0])+1);memcpy(data+offsets[0]+strlen(names[0])+1,names[1],strlen(names[1])+1);
    v=htonl(8);memcpy(data+offsets[1],&v,4);v=htonl(0);memcpy(data+offsets[1]+4,&v,4);
    if(added==3){memcpy(data+offsets[2],versions[0],strlen(versions[0])+1);}
    free(old);return result;
}
'''


class ProvidesPipelineTests(unittest.TestCase):
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
        temporary = tempfile.TemporaryDirectory(prefix='s4-provides-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.library = Path(temporary.name) / 'librpm-provides-model.so'
        source = effects.LIBRARY.replace('void *headerExport(', 'void *fixtureProvidesOriginalExport(') + PROVIDES_MODEL
        source += (effects.SOURCE.parent / 'Updates.Tests/rpm_version_model.c').read_text()
        source += (effects.SOURCE.parent / 'Updates.Tests/rpm_range_model.c').read_text()
        source += (effects.SOURCE.parent / 'Updates.Tests/rpm_dependency_model.c').read_text()
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=source, text=True, capture_output=True, check=True)

    def test_fresh_test_binds_distinct_installed_and_incoming_declared_capabilities(self):
        self.prepare(userland_removal=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout); receipt = proof['provides_observation']
        installed, incoming = receipt['owners']
        self.assertEqual(bytes.fromhex(installed['provides'][0]['name_hex']), b'virtual-capability')
        self.assertEqual(bytes.fromhex(incoming['provides'][0]['name_hex']), b'userland')
        self.assertEqual(receipt['provides'], 4); self.assertEqual(installed['instance'], 1)
        self.assertEqual(incoming['header_sha256'], proof['effects']['incoming'][0]['header_sha256'])
        self.assertEqual(proof['effects']['removals'][0]['provides'], proof['effects']['installed_provides'][0]['provides'])
        original = copy.deepcopy(proof)
        for name in ('trigger_input_observation', 'file_trigger_prefix_observation', 'trigger_condition_observation',
                     'trigger_range_observation', 'provides_observation', 'provider_match_observation', 'trigger_source_observation', 'header_input_observation', 'header_match_observation', 'trigger_first_observation', 'header_iteration_observation', 'trigger_count_observation', 'trigger_argument_observation', 'trigger_iterator_observation', 'trigger_walk_observation', 'transaction_element_observation', 'psm_goal_observation', 'psm_input_observation', 'psm_route_observation', 'psm_failure_observation'): original.pop(name)
        self.assertEqual(receipt['input_sha256'], hashlib.sha256((json.dumps(original, sort_keys=True) + '\n').encode()).hexdigest())
        self.assertFalse(receipt['package_trigger_matches_observed']); self.assertFalse(proof['installation_authorized'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_partial_declared_provides_refuse_before_test_without_output_or_pointer_change(self):
        self.prepare(provides_partial=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell(expected=75)
        self.assertIn('Provides projection is missing or has incomplete arrays', result.stderr)
        self.assertNotIn('run 1', self.native_calls()); self.assertEqual(result.stdout, '')
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': False,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}

    def test_partial_provides_keep_existing_effects_component_pending(self):
        self.prepare(provides_partial=True)
        self.shell('s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())

    def test_interpreter_and_removal_native_bases_keep_projection_disabled(self):
        original = self.library
        try:
            for base, fixture, body in (
                (interpreters.LIBRARY, interpreters.UpdateInterpreterIntegrationTests, 's4_check_update_interpreters'),
                (effects.LIBRARY, removals.UpdateRemovalIntegrationTests, 's4_check_update_removals')):
                self.library = self.root / 'bypass-model.so'
                source = base.replace('void *headerExport(', 'void *fixtureProvidesOriginalExport(') + PROVIDES_MODEL
                source += (effects.SOURCE.parent / 'Updates.Tests/rpm_version_model.c').read_text()
                subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(self.library)],
                               input=source, text=True, capture_output=True, check=True)
                self.prepare(provides_partial=True)
                proof = json.loads(fixture.shell(self, body).stdout)
                self.assertNotIn('installed_provides', proof['effects'])
                self.assertNotIn('provides', proof['effects']['incoming'][0])
                self.assertNotIn('provides_observation', proof)
        finally: self.library = original

    def test_missing_projection_delivery_refuses_after_fresh_test_despite_stale_receipt(self):
        self.prepare(); pointer = (self.root / 'state/updates/current.json').read_bytes()
        delivered = triggers.emitted().replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        ending = "if trigger_execution:\n    raise SystemExit(trigger_main(psm_failure_observe))\n"
        self.assertTrue(delivered.endswith(ending))
        # Explicit private parent-delivery MODEL: the actual guard sees a
        # missing source projection after the completed unchanged native TEST.
        delivered = delivered[:-len(ending)] + (
            "def missing_projection(proof):\n"
            "    proof['effects'].pop('installed_provides')\n"
            "    proof['provides_observation'] = {'declared_provides_observed': True}\n"
            "    return provides_observe(proof)\n"
            "if trigger_execution:\n    raise SystemExit(trigger_main(missing_projection))\n")
        model_path = self.root / 'missing-projection-model.py'
        model_path.write_text(delivered)
        override = 's4_update_trigger_inputs_program() { cat ' + shlex.quote(str(model_path)) + '; }\n'
        result = self.shell(override + 's4_check_update_effects', expected=75)
        self.assertIn('installed_provides', result.stderr); self.assertIn('run 1', self.native_calls())
        self.assertEqual(result.stdout, ''); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'explicit_parent_delivery_model': 'remove installed_provides and insert stale receipt before calling unchanged provides_observe',
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'real_installs_or_scripts': False}


if __name__ == '__main__': unittest.main()

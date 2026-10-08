import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_update_effects as effects


def emitted():
    return subprocess.check_output(['bash', '-c', 'source "$1"; s4_update_trigger_inputs_program',
        'fixture', str(effects.SOURCE)], text=True)


def trigger_entries(family='transfiletrigger', scripts=2, indexes=(0, 0, 1), senses=None,
                    script_flags=True, priorities=True):
    tags = {'trigger': (1065,1092,5027,1066,1067,1068,1069,None),
            'filetrigger': (5066,5067,5068,5069,5071,5072,5070,5084),
            'transfiletrigger': (5076,5077,5078,5079,5081,5082,5080,5085)}[family]
    body, program, flags, names, versions, phase, index, priority = tags
    count = len(indexes)
    values = [(body,8,[b'opaque %{macro} $(command)']*scripts),
        (program,8,[b'/bin/sh']*scripts), (names,8,[b'/declared/prefix']*count),
        (versions,8,[b'']*count), (phase,4,list(senses or [65536]*count)), (index,4,list(indexes))]
    if script_flags: values.append((flags,4,[0]*scripts))
    if priority and priorities: values.append((priority,4,[1000000]*scripts))
    return values


class TriggerArrayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = emitted(); cls.namespace = {'__name__':'trigger_fixture_library'}
        exec(compile(cls.program, '<emitted-trigger-library>', 'exec'), cls.namespace)

    def owner(self, entries=None):
        return self.namespace['audit_header'](effects.exported(entries or trigger_entries()))

    def groups(self, entries=None):
        return self.namespace['trigger_groups'](self.owner(entries))

    def test_all_three_families_bind_script_slots_and_many_conditions(self):
        for family in ('trigger','filetrigger','transfiletrigger'):
            with self.subTest(family=family):
                result = self.groups(trigger_entries(family,senses=(65536,65536,131072)))[0]
                self.assertEqual((result['family'],result['scripts'],result['conditions']), (family,2,3))
                self.assertEqual([slot['condition_positions'] for slot in result['slots']], [[0,1],[2]])
                self.assertEqual([slot['declared_phase_mask'] for slot in result['slots']], [65536,131072])

    def test_nonmonotonic_and_duplicate_indexes_preserve_source_condition_positions(self):
        result = self.groups(trigger_entries(indexes=(1,0,1)))[0]
        self.assertEqual([slot['condition_positions'] for slot in result['slots']], [[1],[0,2]])

    def test_absent_script_flags_are_recorded_without_inventing_execution_policy(self):
        result = self.groups(trigger_entries(script_flags=False))[0]
        self.assertEqual([slot['script_flags'] for slot in result['slots']], [None,None])

    def test_priority_is_per_script_and_ordinary_triggers_have_no_priority_array(self):
        self.assertEqual([slot['priority'] for slot in self.groups()[0]['slots']], [1000000,1000000])
        self.assertEqual([slot['priority'] for slot in self.groups(trigger_entries('trigger'))[0]['slots']], [None,None])

    def test_missing_each_required_array_refuses_the_complete_family(self):
        entries = trigger_entries()
        for omitted in (5076,5077,5079,5081,5082,5080,5085):
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, 'incomplete declared arrays'):
                self.groups([entry for entry in entries if entry[0] != omitted])

    def test_mismatched_program_flags_and_priority_lengths_refuse(self):
        for tag in (5077,5078,5085):
            entries = [(number,kind,values[:1] if number==tag else values) for number,kind,values in trigger_entries()]
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, 'counts do not correspond'):
                self.groups(entries)

    def test_mismatched_condition_arrays_refuse(self):
        for tag in (5081,5082,5080):
            entries = [(number,kind,values[:1] if number==tag else values) for number,kind,values in trigger_entries()]
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, 'counts do not correspond'):
                self.groups(entries)

    def test_out_of_range_and_uint32_max_indexes_refuse_before_indexing(self):
        for index in (2,2**32-1):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'condition index'):
                self.groups(trigger_entries(indexes=(0,1,index)))

    def test_unreferenced_script_slots_refuse(self):
        with self.assertRaisesRegex(ValueError, 'no declared condition'):
            self.groups(trigger_entries(indexes=(0,0)))

    def test_mixed_zero_and_multiple_phases_refuse(self):
        for senses in ((65536,131072,131072), (0,0,131072), (65536|131072,65536|131072,131072)):
            with self.subTest(senses=senses), self.assertRaisesRegex(ValueError, 'declared phases'):
                self.groups(trigger_entries(senses=senses))

    def test_prein_is_supported_only_for_ordinary_trigger_family(self):
        entries = trigger_entries('trigger',senses=(1<<25,1<<25,1<<25))
        self.assertEqual(self.groups(entries)[0]['slots'][0]['declared_phase_mask'],1<<25)
        for family in ('filetrigger','transfiletrigger'):
            with self.subTest(family=family), self.assertRaisesRegex(ValueError,'declared phases'):
                self.groups(trigger_entries(family,senses=(1<<25,1<<25,1<<25)))

    def test_nonphase_sense_bits_and_script_flags_remain_uninterpreted_metadata(self):
        entries = trigger_entries(senses=(65536|2|1<<29,65536|8,131072))
        entries = [(tag,kind,[2**32-1]*2 if tag==5078 else values) for tag,kind,values in entries]
        self.assertEqual(self.groups(entries)[0]['slots'][0]['script_flags'],2**32-1)

    def test_empty_condition_names_and_empty_program_declarations_refuse(self):
        for tag in (5077,5079):
            entries = [(number,kind,[b'']*len(values) if number==tag else values) for number,kind,values in trigger_entries()]
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError,'name is empty'):
                self.groups(entries)

    def test_body_condition_and_version_text_stay_opaque_and_unevaluated(self):
        entries = trigger_entries(); entries = [(tag,kind,[b'\xff$(false)']*len(values) if tag in (5076,5079,5081) else values) for tag,kind,values in entries]
        owner = self.owner(entries); self.namespace['trigger_groups'](owner)
        self.assertNotIn('false',json.dumps(owner)); self.assertNotIn('macro',json.dumps(owner))

    def test_disclosed_integer_and_program_digests_must_match_the_actual_values(self):
        for tag in (5078,5077):
            owner = self.owner(); entry = next(entry for entry in owner['tags'] if entry['tag']==tag)
            entry['values'][0] = 1 if tag==5078 else '/bin/xx'
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError,'digest is inconsistent'):
                self.namespace['trigger_groups'](owner)

    def test_boolean_counts_unknown_tags_bad_lengths_and_duplicate_records_refuse(self):
        for field,value in (('count',True),('tag',9999),('bytes',1),('sha256','not-a-digest')):
            owner = self.owner(); owner['tags'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):self.namespace['trigger_groups'](owner)
        owner = self.owner(); owner['tags'].append(copy.deepcopy(owner['tags'][-1]))
        with self.assertRaises(ValueError):self.namespace['trigger_groups'](owner)

    def test_no_trigger_tags_do_not_claim_correspondence_for_a_scriptless_owner(self):
        owner = self.owner([(1000,6,[b'fixture'])]);self.assertEqual(self.namespace['trigger_groups'](owner),[])

    def test_each_raw_family_count_remains_bounded_by_the_existing_decoder(self):
        with self.assertRaisesRegex(ValueError,'type/count'):
            self.owner([(5076,8,[b'']*4097)])


class TriggerProofTests(unittest.TestCase):
    namespace = None

    @classmethod
    def setUpClass(cls):
        cls.program = emitted();cls.namespace = {'__name__':'trigger_fixture_library'}
        exec(compile(cls.program,'<emitted-trigger-library>','exec'),cls.namespace)

    def proof(self, trigger=True, incoming=True):
        material = effects.exported(trigger_entries(scripts=1,indexes=(0,)) if trigger else [(1000,6,[b'fixture'])])
        audited = self.namespace['audit_header'](material)
        owner = {'instance':1,'name':'fixture','nevra':'fixture-0-1.x86_64', **audited,
            'file_trigger_prefix_bytes':self.namespace['file_trigger_export'](material,audited)}
        baseline = {'headers':1,'sha256':hashlib.sha256(json.dumps([(1,owner['header_sha256'])],separators=(',',':')).encode()).hexdigest()}
        additions = [{'file':'packages/0.rpm','sha256':'a'*64,'bytes':15,'nevra':'future-1-1.x86_64'}] if incoming else []
        incoming_owners = [{'name':'future',**additions[0],**self.namespace['audit_header'](effects.exported([(1023,6,[b'body'])])),
                            'file_trigger_prefix_bytes':[]}] if incoming else []
        return {'schema':1,'test_passed':True,'rpm_test_performed':incoming,
            **{flag:False for flag in ('installs_performed','scripts_executed','installation_authorized','storage_capacity_checked','freshness_proven')},
            'baseline':baseline,'additions':additions,'removals':[],
            'effects':{'schema':1,'incoming':incoming_owners,'removals':[],'installed_script_owners':[owner] if trigger else [],
                'installed_versions':self.namespace['installed_version_inventory']({1:owner},baseline),
                'installed_headers_observed':1,'script_metadata_observed':True,'removals_bound_to_installed_instances':True,
                **{flag:False for flag in ('installed_headers_authenticated','trigger_selection_complete','script_execution_plan_complete',
                    'script_policy_satisfied','removal_policy_satisfied','rollback_policy_satisfied')}}}

    def test_complete_observed_inventory_and_header_bound_owner_produce_only_qualified_correspondence(self):
        result=self.namespace['trigger_observe'](self.proof())['trigger_input_observation']
        self.assertEqual((result['script_slots'],result['condition_references']),(1,1));self.assertTrue(result['declared_arrays_correspond'])
        self.assertEqual(result['owners'][0]['instance'],1);self.assertEqual(result['owners'][1]['file'],'packages/0.rpm')
        for flag in ('condition_text_available','conditions_evaluated','trigger_selection_complete','transaction_file_actions_observed',
                     'execution_order_complete','script_execution_plan_complete','installed_headers_authenticated',
                     'script_policy_satisfied','removal_policy_satisfied','rollback_policy_satisfied','installation_authorized','scripts_executed','server_ready'):
            self.assertIs(result[flag],False)

    def test_empty_incoming_batch_and_no_triggers_withhold_positive_correspondence(self):
        result=self.namespace['trigger_observe'](self.proof(trigger=False,incoming=False))['trigger_input_observation']
        self.assertFalse(result['declared_arrays_correspond']);self.assertEqual(result['script_slots'],0)

    def test_forged_baseline_inventory_hash_count_or_sorted_instance_order_refuse(self):
        for mutation in ('baseline','bytes','hash','count','schema'):
            proof=self.proof();source=proof['effects']['installed_versions']
            if mutation=='baseline':proof['baseline']['sha256']='b'*64
            elif mutation=='bytes':source['entries_bytes']+=1
            elif mutation=='hash':source['entries_sha256']='b'*64
            elif mutation=='count':source['headers']=True
            else:source['schema']=True
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.namespace['trigger_observe'](proof)

    def test_missing_native_participation_or_true_and_numeric_authority_flags_refuse(self):
        for mutation in ('test','audit','empty-test','authority','inventory-authority'):
            proof=self.proof()
            if mutation=='test':proof['test_passed']=False
            elif mutation=='audit':proof['effects']['script_metadata_observed']=False
            elif mutation=='empty-test':proof['rpm_test_performed']=False
            elif mutation=='authority':proof['installation_authorized']=True
            else:proof['effects']['installed_versions']['snapshot_atomic']=0
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.namespace['trigger_observe'](proof)

    def test_wrong_owner_header_instance_and_duplicate_installed_owner_refuse(self):
        for mutation in ('header','instance','duplicate'):
            proof=self.proof();owner=proof['effects']['installed_script_owners'][0]
            if mutation=='header':owner['header_sha256']='b'*64
            elif mutation=='instance':owner['instance']=2
            else:proof['effects']['installed_script_owners'].append(copy.deepcopy(owner))
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.namespace['trigger_observe'](proof)

    def test_foreign_snapshot_missing_addition_and_duplicate_incoming_refuse(self):
        for mutation in ('hash','missing','duplicate'):
            proof=self.proof()
            if mutation=='hash':proof['effects']['incoming'][0]['sha256']='b'*64
            elif mutation=='missing':proof['additions']=[]
            else:proof['effects']['incoming'].append(copy.deepcopy(proof['effects']['incoming'][0]))
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.namespace['trigger_observe'](proof)

    def test_bound_removal_preserves_actual_instance_and_native_order(self):
        proof=self.proof();owner=copy.deepcopy(proof['effects']['installed_script_owners'][0]);owner['classification']='other-removal'
        proof['effects']['removals']=[owner];proof['removals']=[owner['nevra']]
        self.assertEqual(self.namespace['trigger_observe'](proof)['trigger_input_observation']['removed_instances'],[1])

    def test_removed_owner_tag_swap_duplicate_instance_or_foreign_order_refuse(self):
        for mutation in ('tags','duplicate','order'):
            proof=self.proof();owner=copy.deepcopy(proof['effects']['installed_script_owners'][0]);owner['classification']='other-removal'
            proof['effects']['removals']=[owner];proof['removals']=[owner['nevra']]
            if mutation=='tags':owner['tags']=[]
            elif mutation=='duplicate':proof['effects']['removals'].append(copy.deepcopy(owner));proof['removals']*=2
            else:proof['removals']=['foreign-0-1.x86_64']
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.namespace['trigger_observe'](proof)

    def test_aggregate_slot_and_condition_bounds_refuse_many_individually_valid_owners(self):
        for scripts, references, count in ((4096, tuple(range(4096)), 3), (1, (0,)*4096, 17)):
            with self.subTest(scripts=scripts,owners=count):
                proof=self.proof(incoming=False)
                template=self.namespace['audit_header'](effects.exported(trigger_entries(scripts=scripts,indexes=references)))
                owners=[{'instance':number,'name':f'fixture{number}','nevra':f'fixture{number}-0-1.x86_64',
                         **copy.deepcopy(template)} for number in range(1,count+1)]
                proof['baseline']={'headers':count,'sha256':hashlib.sha256(json.dumps(
                    [(owner['instance'],owner['header_sha256']) for owner in owners],separators=(',',':')).encode()).hexdigest()}
                proof['effects']['installed_headers_observed']=count
                proof['effects']['installed_script_owners']=owners
                proof['effects']['installed_versions']=self.namespace['installed_version_inventory'](
                    {owner['instance']:owner for owner in owners},proof['baseline'])
                with self.assertRaisesRegex(ValueError,'aggregate work bound'):self.namespace['trigger_observe'](proof)


class TriggerPrivateInputTests(unittest.TestCase):
    proof = TriggerProofTests.proof

    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='s4-trigger-input-',dir=Path.home()/'.cache');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.program=self.root/'triggers.py';self.program.write_text(emitted())
        self.namespace={'__name__':'trigger_fixture_library'};exec(compile(self.program.read_text(),'<trigger-library>','exec'),self.namespace)
        self.path=self.root/'result.json';self.path.write_text(json.dumps(self.proof(),sort_keys=True)+'\n');self.path.chmod(0o600)

    def run_guard(self,expected=0):
        result=subprocess.run(['python3','-I',str(self.program),str(self.root)],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,expected,result.stderr)
        if expected:self.assertEqual(result.stdout,'');self.assertIn('declared trigger inputs deferred',result.stderr)
        return result

    def test_actual_private_snapshot_eof_and_hash_precede_json(self):
        material=self.path.read_bytes();result=self.run_guard();receipt=json.loads(result.stdout)['trigger_input_observation']
        self.assertEqual(receipt['input_sha256'],hashlib.sha256(material).hexdigest());self.assertEqual(self.path.read_bytes(),material)

    def test_fifo_symlink_directory_and_public_mode_refuse_without_mutation(self):
        original=self.path.read_bytes()
        for kind in ('fifo','symlink','directory','mode'):
            with self.subTest(kind=kind):
                self.path.unlink()
                if kind=='fifo':os.mkfifo(self.path,0o600)
                elif kind=='symlink':self.path.symlink_to(self.program)
                elif kind=='directory':self.path.mkdir(mode=0o700)
                else:self.path.write_bytes(original);self.path.chmod(0o644)
                before=self.path.lstat();self.run_guard(expected=75);after=self.path.lstat()
                self.assertEqual((before.st_dev,before.st_ino,before.st_mode),(after.st_dev,after.st_ino,after.st_mode))
                if kind=='directory':self.path.rmdir()
                else:self.path.unlink()
                self.path.write_bytes(original);self.path.chmod(0o600)

    def test_duplicate_json_keys_and_partial_invalid_proof_publish_nothing(self):
        self.path.write_text('{"schema":1,"schema":1}');self.run_guard(expected=75)
        self.path.write_text('{"schema":1}');self.run_guard(expected=75)

    def test_real_snapshot_inode_swap_before_open_refuses(self):
        injection="_original_open=os.open\ndef _swap(path,flags,mode=0o777,*,dir_fd=None):\n    path=Path(path)\n    if path.name=='result.json':\n        path.rename(path.with_name('saved-result'));path.write_bytes(path.with_name('saved-result').read_bytes());path.chmod(0o600)\n    return _original_open(path,flags,mode,dir_fd=dir_fd)\nos.open=_swap\n"
        self.program.write_text(self.program.read_text().replace("if __name__ == '__main__':",injection+"\nif __name__ == '__main__':"))
        self.assertIn('changed before reading',self.run_guard(expected=75).stderr)

    def test_checked_ordinary_stream_close_failure_cannot_publish_json(self):
        injection="_original_fdopen=os.fdopen\nclass _Closing:\n    def __init__(self,*args):self.stream=_original_fdopen(*args)\n    def __enter__(self):return self.stream.__enter__()\n    def __exit__(self,*args):\n        self.stream.__exit__(*args);raise OSError('trigger checked-close delivery')\nos.fdopen=_Closing\n"
        self.program.write_text(self.program.read_text().replace("if __name__ == '__main__':",injection+"\nif __name__ == '__main__':"))
        self.assertIn('checked-close delivery',self.run_guard(expected=75).stderr)

    def test_complete_output_bound_withholds_json_after_a_valid_input_model(self):
        # Only the byte-limit constant is scaled; input remains valid and all
        # ordinary correspondence/cleanup predicates run before serialization.
        limit=len(self.path.read_bytes())+1
        self.program.write_text(self.program.read_text().replace('TRIGGER_LIMIT = 32 * 1024 * 1024',f'TRIGGER_LIMIT = {limit}'))
        self.assertIn('complete output bound',self.run_guard(expected=75).stderr)


class TriggerPipelineTests(unittest.TestCase):
    command=effects.UpdateEffectsTests.command
    configure=effects.UpdateEffectsTests.configure
    calls=effects.UpdateEffectsTests.calls
    setUp=effects.UpdateEffectsTests.setUp
    header=effects.UpdateEffectsTests.header
    prepare=effects.UpdateEffectsTests.prepare
    native_calls=effects.UpdateEffectsTests.native_calls
    setUpClass=classmethod(effects.UpdateEffectsTests.setUpClass.__func__)
    def shell(self,body='s4_check_update_effects',expected=0,timeout=90):
        return effects.UpdateEffectsTests.shell(self,body,expected,timeout)

    def test_fresh_effects_diagnostic_binds_declared_group_to_same_snapshot_and_installed_owner(self):
        self.prepare(userland_removal=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        proof=json.loads(self.shell().stdout);receipt=proof['trigger_input_observation']
        self.assertEqual((receipt['script_slots'],receipt['condition_references']),(1,1))
        self.assertEqual(receipt['owners'][0]['instance'],1);self.assertEqual(receipt['removed_instances'],[1])
        source=copy.deepcopy(proof);source.pop('trigger_input_observation');source.pop('file_trigger_prefix_observation')
        self.assertEqual(receipt['input_sha256'],hashlib.sha256((json.dumps(source,sort_keys=True)+'\n').encode()).hexdigest())
        self.assertFalse(receipt['trigger_selection_complete']);self.assertFalse(proof['installation_authorized'])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'proof':proof,'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified':True,'real_installs_or_scripts':False}

    def test_incomplete_priority_and_out_of_range_index_fail_after_current_test_without_publication(self):
        for flag,reason in (('trigger_missing_priority','incomplete declared arrays'),('trigger_bad_index','condition index')):
            with self.subTest(flag=flag):
                self.prepare(userland_removal=True,**{flag:True});pointer=(self.root/'state/updates/current.json').read_bytes()
                result=self.shell(expected=75);self.assertIn(reason,result.stderr);self.assertIn('run 1',self.native_calls())
                self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'exit':75,'stdout':result.stdout,'stderr':result.stderr,'native_test_seen':True,
            'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified':True,'real_installs_or_scripts':False}

    def test_new_correspondence_refusal_keeps_existing_effects_component_pending(self):
        self.prepare(trigger_bad_index=True);self.shell('s4_reconcile_component update-effects yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-effects').read_text())

    def test_existing_effects_cli_emits_the_guard_without_a_new_cli_or_default_component(self):
        self.prepare();proof=json.loads(self.shell('s4_check_update_effects').stdout)
        self.assertTrue(proof['trigger_input_observation']['declared_arrays_correspond'])
        self.assertIn('server_ready=no',self.shell('s4_status').stdout)


if __name__=='__main__':unittest.main()

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import test_update_compatibility as compatibility
import test_update_interpreters as interpreters


ROOT = Path(__file__).resolve().parents[1]


class InterpreterPathTests(unittest.TestCase):
    setUpClass = classmethod(interpreters.InterpreterObservationTests.setUpClass.__func__)
    make_proof = interpreters.InterpreterObservationTests.make_proof

    def setUp(self):
        interpreters.InterpreterObservationTests.setUp(self)
        self.proof['namespace_inventory'] = {'schema': 1, 'incoming': [], 'removals': [], 'files': 0,
            **{key:False for key in ('installed_headers_authenticated','operation_selection_complete',
                                    'snapshot_atomic','installation_authorized')}}

    def declaration(self, path, mode=stat.S_IFREG|0o755, flags=0, link=''):
        return {'path':path,'bytes':123,'mode':mode,'flags':flags,'link':link}

    def supplied(self, paths, removal=False):
        owner=self.proof['effects']['installed_script_owners'][0].copy()
        if removal:
            self.proof['effects']['removals']=[{**owner,'classification':'same-name-replacement'}]
            self.proof['removals']=[owner['nevra']]
            fields=('name','nevra','header_bytes','header_sha256','instance');kind='removals'
        else:
            owner.update(file='packages/0.rpm',sha256='c'*64,bytes=15)
            self.proof['effects']['incoming']=[owner]
            self.proof['additions']=[{key:owner[key] for key in ('file','sha256','bytes','nevra')}]
            fields=('name','nevra','header_bytes','header_sha256','file','sha256','bytes');kind='incoming'
        self.proof['rpm_test_performed']=True
        self.proof['namespace_inventory'][kind]=[{**{key:owner[key] for key in fields},'files':paths}]
        self.proof['namespace_inventory']['files']=sum(len(row['files']) for name in ('incoming','removals')
                                                      for row in self.proof['namespace_inventory'][name])

    def observe(self):
        proof=self.namespace['observe'](copy.deepcopy(self.proof))
        return self.namespace['interpreter_paths'](proof)

    def test_declared_logical_path_is_bound_to_current_incoming_snapshot(self):
        self.supplied([self.declaration('/bin/sh')])
        result=self.observe()['interpreter_path_correspondence'];hit=result['matches'][0]
        self.assertEqual(hit['relationship'],'declared');self.assertEqual(hit['interpreter'],'/bin/sh')
        self.assertEqual(hit['owner']['file'],'packages/0.rpm');self.assertEqual(hit['owner']['sha256'],'c'*64)
        self.assertTrue(result['potential_literal_path_changes']);self.assertFalse(result['operation_selection_complete'])

    def test_resolved_regular_leaf_and_lookup_alias_directory_are_distinct_correspondences(self):
        self.supplied([self.declaration('/usr/bin/shell'),self.declaration('/bin',stat.S_IFLNK|0o777,link='usr/bin'),
                       self.declaration('/usr/bin',stat.S_IFDIR|0o755)])
        result=self.observe()['interpreter_path_correspondence']
        self.assertEqual([row['relationship'] for row in result['matches']],
                         ['resolved','lookup-ancestor-or-link','lookup-ancestor-or-link'])
        self.assertEqual(result['declared_files'],3)

    def test_removal_path_keeps_installed_instance_and_header_digest_without_authenticating_it(self):
        self.supplied([self.declaration('/usr/bin/shell')],removal=True)
        result=self.observe()['interpreter_path_correspondence'];hit=result['matches'][0]
        self.assertEqual(hit['source'],'removal');self.assertEqual(hit['owner']['instance'],1)
        self.assertEqual(hit['owner']['header_sha256'],self.proof['effects']['removals'][0]['header_sha256'])
        self.assertFalse(result['installed_headers_authenticated'])

    def test_unrelated_paths_are_only_literal_nonmatches_not_interpreter_continuity(self):
        self.supplied([self.declaration('/usr/share/unrelated')])
        result=self.observe()['interpreter_path_correspondence']
        self.assertEqual(result['matches'],[]);self.assertFalse(result['potential_literal_path_changes'])
        for flag in ('alternate_aliases_checked','hardlink_effects_checked','interpreter_transaction_continuity_proven'):
            self.assertFalse(result[flag])

    def test_root_directory_declaration_is_an_observed_lookup_match_not_actual_change_proof(self):
        self.supplied([self.declaration('/',stat.S_IFDIR|0o755)])
        hit=self.observe()['interpreter_path_correspondence']['matches'][0]
        self.assertEqual(hit['declaration']['path'],'/');self.assertEqual(hit['relationship'],'lookup-ancestor-or-link')

    def test_ghost_and_directory_flags_are_preserved_without_operation_selection(self):
        self.supplied([self.declaration('/usr/bin',stat.S_IFDIR|0o755,flags=64)])
        result=self.observe()['interpreter_path_correspondence']
        self.assertEqual(result['matches'][0]['declaration']['flags'],64)
        self.assertFalse(result['operation_selection_complete'])

    def test_empty_batch_has_complete_empty_literal_correspondence_only(self):
        result=self.observe()['interpreter_path_correspondence']
        self.assertEqual(result['matches'],[]);self.assertEqual(result['declared_files'],0)
        self.assertTrue(result['literal_path_correspondence_complete']);self.assertFalse(result['server_ready'])

    def test_lua_declarations_do_not_invent_external_files_or_engines(self):
        self.proof=self.make_proof([(1153,6,[b'<lua>'])])
        self.proof['namespace_inventory']={'schema':1,'incoming':[],'removals':[],'files':0,
            **{key:False for key in ('installed_headers_authenticated','operation_selection_complete','snapshot_atomic','installation_authorized')}}
        result=self.observe();self.assertEqual(result['interpreters']['files'],[])
        self.assertEqual(result['interpreter_path_correspondence']['matches'],[])
        self.assertFalse(result['interpreters']['embedded_engines_tested'])

    def test_complete_compact_namespace_digest_corresponds_to_supplied_bound_records(self):
        self.supplied([self.declaration('/bin/sh')])
        data=json.dumps(self.proof['namespace_inventory'],sort_keys=True,separators=(',',':')).encode()
        self.assertEqual(self.observe()['interpreter_path_correspondence']['inventory_sha256'],hashlib.sha256(data).hexdigest())

    def test_missing_claimed_or_wrong_typed_namespace_qualifiers_refuse(self):
        for key,value in (('schema',True),('incoming',{}),('removals',{}),('installation_authorized',True),
                          ('snapshot_atomic',True),('installed_headers_authenticated',True)):
            old=self.proof['namespace_inventory'][key];self.proof['namespace_inventory'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.observe()
            self.proof['namespace_inventory'][key]=old
        del self.proof['namespace_inventory']
        with self.assertRaises(KeyError):self.observe()

    def test_owner_header_snapshot_or_instance_correspondence_is_required(self):
        for removal in (False,True):
            self.supplied([self.declaration('/bin/sh')],removal=removal)
            row=self.proof['namespace_inventory']['removals' if removal else 'incoming'][0]
            for key,value in (('header_sha256','f'*64),('nevra','foreign-1-1.x86_64'),
                              ('instance',2) if removal else ('sha256','f'*64)):
                old=row[key];row[key]=value
                with self.subTest(removal=removal,key=key),self.assertRaises(ValueError):self.observe()
                row[key]=old

    def test_missing_extra_or_repeated_namespace_owners_do_not_become_complete(self):
        self.supplied([self.declaration('/bin/sh')]);row=self.proof['namespace_inventory']['incoming'][0]
        for values in ([],[row,row]):
            self.proof['namespace_inventory']['incoming']=values
            with self.subTest(values=values),self.assertRaises(ValueError):self.observe()

    def test_repeated_or_noncanonical_paths_refuse_without_modifying_observed_files(self):
        before=self.executable.read_bytes()
        for path in ('relative','/usr/../bin/sh','/usr//bin/sh','/bin/sh\n'):
            self.supplied([self.declaration(path)])
            with self.subTest(path=path),self.assertRaises(ValueError):self.observe()
        self.supplied([self.declaration('/bin/sh'),self.declaration('/bin/sh')])
        with self.assertRaises(ValueError):self.observe()
        self.assertEqual(self.executable.read_bytes(),before)

    def test_wrong_metadata_types_limits_or_symlink_attributes_refuse(self):
        for key,value in (('bytes',True),('bytes',16*1024**3+1),('mode',65536),('flags',True),
                          ('flags',2**32),('link','invalid-regular-target')):
            item=self.declaration('/bin/sh');item[key]=value;self.supplied([item])
            with self.subTest(key=key),self.assertRaises(ValueError):self.observe()
        self.supplied([self.declaration('/bin/sh',stat.S_IFLNK|0o777)])
        with self.assertRaises(ValueError):self.observe()

    def test_declared_count_and_total_path_bound_cannot_be_partial_success(self):
        self.supplied([self.declaration('/bin/sh')]);self.proof['namespace_inventory']['files']=0
        with self.assertRaises(ValueError):self.observe()
        row=self.proof['namespace_inventory']['incoming'][0];row['files']=[{}]*131073
        with self.assertRaisesRegex(ValueError,'count bound|inventory exceeds'):self.observe()

    def test_match_limit_refuses_instead_of_truncating_observed_correspondence(self):
        self.supplied([self.declaration('/bin/sh')])
        old=self.namespace['INTERPRETER_MATCH_LIMIT'];self.namespace['INTERPRETER_MATCH_LIMIT']=0
        try:
            with self.assertRaisesRegex(ValueError,'match bound'):self.observe()
        finally:self.namespace['INTERPRETER_MATCH_LIMIT']=old

    def test_lookup_inventory_missing_reordered_or_unbounded_refuses(self):
        self.supplied([self.declaration('/bin/sh')]);proof=self.namespace['observe'](copy.deepcopy(self.proof))
        for paths in ([],['/bin/sh'],proof['interpreters']['files'][0]['lookup_paths'][::-1],['/']*1027):
            value=copy.deepcopy(proof);value['interpreters']['files'][0]['lookup_paths']=paths
            with self.subTest(paths=paths),self.assertRaises(ValueError):self.namespace['interpreter_paths'](value)

    def test_all_twelve_policy_authority_flags_stay_false(self):
        self.supplied([self.declaration('/bin/sh')]);result=self.observe()['interpreter_path_correspondence']
        for flag in ('installed_headers_authenticated','operation_selection_complete','alternate_aliases_checked',
                     'hardlink_effects_checked','future_interpreter_bytes_authenticated','transaction_order_complete',
                     'interpreter_transaction_continuity_proven','execution_policy_satisfied','snapshot_atomic',
                     'installation_authorized','scripts_executed','server_ready'):
            self.assertIs(result[flag],False)


# Public file-array/query error MODEL. Paths are declarations, not RPM payloads.
PATH_LIBRARY=interpreters.LIBRARY
PATH_LIBRARY=PATH_LIBRARY.replace('void *rpmtsInitIterator(', 'void *oldPathIterator(')
PATH_LIBRARY=PATH_LIBRARY.replace('const char *rpmfiFN(', 'const char *oldPathName(')
PATH_LIBRARY+=r'''
void *rpmtsInitIterator(TS *ts,int tag,void *key,size_t length) {
    if(tag || (key && length!=sizeof(unsigned))) abort();
    if(key && *(unsigned*)key!=1) abort();
    if(key && setting("query_absent")) return NULL;
    ts->iteration=0;record("query",key?1:0);return ts;
}
const char *rpmfiFN(FI *fi) {
    if(setting("fi_duplicate")) return "/bin/sh";
    return fi->index ? "/usr/share/interpreter-path-fixture" :
        (setting("path_unrelated") ? "/usr/share/unrelated" : "/bin/sh");
}
'''


class InterpreterPathPipelineTests(unittest.TestCase):
    temporary_parent=compatibility.admission.protected_model_parent()
    command=compatibility.UpdateCompatibilityTests.command
    configure=compatibility.UpdateCompatibilityTests.configure
    calls=compatibility.UpdateCompatibilityTests.calls
    setUp=compatibility.UpdateCompatibilityTests.setUp
    header=compatibility.UpdateCompatibilityTests.header
    prepare=compatibility.UpdateCompatibilityTests.prepare
    native_calls=compatibility.UpdateCompatibilityTests.native_calls
    shell=interpreters.UpdateInterpreterIntegrationTests.shell

    @classmethod
    def setUpClass(cls):
        temporary=tempfile.TemporaryDirectory(prefix='s4-interpreter-path-abi-',dir=Path.home()/'.cache')
        cls.addClassCleanup(temporary.cleanup);cls.library=Path(temporary.name)/'librpm-interpreter-path-model.so'
        subprocess.run(['cc','-shared','-fPIC','-x','c','-','-o',str(cls.library)],input=PATH_LIBRARY,
                       text=True,capture_output=True,check=True)

    def test_current_signed_snapshot_and_removed_instance_paths_match_observed_real_shell(self):
        self.prepare(userland_removal=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        proof=json.loads(self.shell().stdout);guard=proof['interpreter_path_correspondence']
        self.assertEqual(guard['declared_files'],4);self.assertEqual(len(guard['matches']),2)
        self.assertEqual({row['source'] for row in guard['matches']},{'incoming','removal'})
        self.assertEqual(guard['matches'][0]['owner']['sha256'],proof['additions'][0]['sha256'])
        self.assertEqual(guard['matches'][1]['owner']['instance'],proof['effects']['removals'][0]['instance'])
        self.assertTrue(guard['potential_literal_path_changes']);self.assertFalse(guard['interpreter_transaction_continuity_proven'])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.assertEqual(list((self.root/'run').glob('update-check.*')),[])
        self.assertIn('query 1',self.native_calls())
        self.record={'scope':'Current client/TEST/lookup/correspondence over finite C file/query/namespace/signature MODEL; actual root-owned Debian shell observations without executing it',
                     'proof':proof,'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'native_calls':self.native_calls(),'real_installs_or_scripts':False}

    def test_absent_removal_instance_query_withholds_complete_proof_and_preserves_pointer(self):
        self.prepare(userland_removal=True,query_absent=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        result=self.shell(expected=75);self.assertEqual(result.stdout,'')
        self.assertIn('interpreter removal header iterator is unavailable',result.stderr)
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'scope':'Actual current query failure branch with explicit C NULL iterator delivery',
                     'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
                     'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'real_installs_or_scripts':False}

    def test_bad_file_arrays_and_duplicate_paths_cannot_certify_correspondence(self):
        self.prepare(userland_removal=True)
        for flag,reason in (('fi_badtype','signed basename array type is invalid'),
                            ('fi_badcount','signed file attribute array type/count differs'),
                            ('fi_short','signed file inventory ended or changed unexpectedly'),
                            ('fi_duplicate','signed file metadata is missing, duplicated or excessive'),
                            ('fi_failure','signed file inventory could not be loaded consistently')):
            self.configure(userland_removal=True,**{flag:True})
            with self.subTest(flag=flag):
                result=self.shell(expected=75)
                self.assertEqual(result.stdout,'');self.assertIn(reason,result.stderr)

    def test_prior_success_does_not_skip_current_namespace_and_retry_can_recover(self):
        self.prepare(userland_removal=True);self.shell('s4_reconcile_component update-interpreters yes')
        self.configure(userland_removal=True,query_absent=True)
        self.shell('s4_reconcile_component update-interpreters yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-interpreters').read_text())
        self.configure(userland_removal=True);self.shell('s4_reconcile_component update-interpreters yes')
        self.assertIn('status=complete',(self.root/'state/components/update-interpreters').read_text())

    def test_unrelated_payload_and_empty_incoming_are_scoped_observations_only(self):
        self.prepare(userland_removal=True,path_unrelated=True)
        proof=json.loads(self.shell().stdout);guard=proof['interpreter_path_correspondence']
        self.assertEqual(guard['matches'],[]);self.assertFalse(guard['interpreter_transaction_continuity_proven'])
        self.configure(empty=True);self.prepare(empty=True)
        proof=json.loads(self.shell().stdout)
        self.assertFalse(proof['rpm_test_performed']);self.assertEqual(proof['interpreter_path_correspondence']['declared_files'],0)

    def test_normal_effects_and_compatibility_modes_do_not_require_or_claim_namespace_inventory(self):
        self.prepare()
        for body in ('s4_check_update_effects','s4_check_updates'):
            proof=json.loads(self.shell(body).stdout)
            self.assertNotIn('namespace_inventory',proof);self.assertNotIn('interpreter_path_correspondence',proof)
        self.assertNotIn('query 1',self.native_calls())


if __name__=='__main__':unittest.main()

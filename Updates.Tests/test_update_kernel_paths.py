import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_update_floors as floors
import test_update_compatibility as compatibility


ROOT=Path(__file__).resolve().parents[1]


class KernelPathTests(unittest.TestCase):
    setUpClass=classmethod(floors.IncomingFloorTests.setUpClass.__func__)
    compare=floors.IncomingFloorTests.compare
    refresh=floors.IncomingFloorTests.refresh
    prepare_floor=floors.IncomingFloorTests.prepare_floor
    invoke=floors.IncomingFloorTests.invoke

    def setUp(self):
        floors.IncomingFloorTests.setUp(self);self.prepare_floor()

    def observe(self):
        proof=self.namespace['observe'](copy.deepcopy(self.proof))
        proof=self.namespace['version_observe'](proof,lambda:self.compare)
        return self.namespace['kernel_paths'](proof,lambda:self.compare)

    def installed(self,name,evr,instance=8,arch='x86_64'):
        self.proof['effects']['installed_versions']['entries'].append({'instance':instance,'name':name,
            'nevra':f'{name}-{evr}.{arch}','header_bytes':64,'header_sha256':hashlib.sha256(str(instance).encode()).hexdigest()})
        self.refresh()

    def test_distinct_release_paths_bind_snapshot_and_complete_current_inventory(self):
        result=self.observe();guard=result['kernel_path_guard'];match=guard['matches'][0]
        self.assertEqual(match['expected_paths'],['/boot/vmlinuz-3-1','/lib/modules/3-1/vmlinuz'])
        self.assertEqual(guard['observed_kernel_identities_considered'],2)
        self.assertEqual(guard['baseline_sha256'],result['baseline']['sha256'])
        self.assertEqual(guard['installed_inventory_sha256'],result['effects']['installed_versions']['entries_sha256'])
        self.assertEqual(match['owner']['sha256'],result['additions'][0]['sha256'])

    def test_higher_epoch_same_version_release_passes_native_floor_but_refuses_path_reuse(self):
        self.prepare_floor(new='9:2-1')
        old=self.namespace['observe'](copy.deepcopy(self.proof));old=self.namespace['version_observe'](old,lambda:self.compare)
        self.assertTrue(self.namespace['floor_observe'](old,lambda:self.compare)['incoming_version_guard']['matched_incoming_strictly_newer'])
        with self.assertRaisesRegex(ValueError,'overlap an observed installed identity'):self.observe()

    def test_collision_with_oldest_kernel_is_not_hidden_by_newest_selection(self):
        self.prepare_floor(new='9:1-1')
        with self.assertRaisesRegex(ValueError,'overlap an observed installed identity'):self.observe()

    def test_epoch_does_not_enter_expected_paths_when_the_release_is_distinct(self):
        self.prepare_floor(new='9:3-1')
        match=self.observe()['kernel_path_guard']['matches'][0]
        self.assertEqual(match['epoch'],'9');self.assertEqual(match['expected_paths'][0],'/boot/vmlinuz-3-1')

    def test_same_expected_paths_from_another_supported_family_refuse(self):
        self.installed('kernel-hwe','3-1')
        with self.assertRaisesRegex(ValueError,'overlap an observed installed identity'):self.observe()

    def test_cross_architecture_other_family_cannot_hide_path_collision(self):
        self.installed('kernel-64k','3-1',arch='aarch64')
        with self.assertRaisesRegex(ValueError,'overlap an observed installed identity'):self.observe()

    def test_vetted_64k_and_hwe_identities_with_distinct_paths_are_supported(self):
        for name,arch in (('kernel-64k','aarch64'),('kernel-hwe','x86_64'),('kernel','aarch64')):
            with self.subTest(name=name,arch=arch):
                self.prepare_floor(name=name,arch=arch)
                self.assertEqual(self.observe()['kernel_path_guard']['incoming_kernel_count'],1)

    def test_unknown_known_family_incoming_or_installed_defers_instead_of_guessing(self):
        for name in ('kernel-mshv','kernel-uvm','kernel-uki'):
            self.prepare_floor()
            self.installed(name,'4-1')
            with self.subTest(name=name,side='installed'),self.assertRaisesRegex(ValueError,'unvetted'):self.observe()
            self.prepare_floor(name=name)
            with self.subTest(name=name,side='incoming'),self.assertRaisesRegex(ValueError,'unvetted'):self.observe()

    def test_unrelated_key_and_kernel_devel_do_not_become_boot_owners(self):
        self.installed('kernel-devel','3-1')
        self.installed('gpg-pubkey','135ce90-66878efc.(none)',instance=9,arch='noarch')
        self.assertEqual(self.observe()['kernel_path_guard']['observed_kernel_identities_considered'],2)
        self.assertFalse(self.observe()['kernel_path_guard']['all_kernel_names_identified'])

    def test_new_family_has_no_installed_floor_and_no_filesystem_absence_proof(self):
        self.prepare_floor(name='kernel-hwe',installed=())
        result=self.observe();guard=result['kernel_path_guard']
        self.assertEqual(guard['observed_kernel_identities_considered'],0)
        self.assertTrue(guard['expected_paths_disjoint']);self.assertFalse(guard['actual_filesystem_collisions_checked'])
        self.assertFalse(result['incoming_version_guard']['matched_incoming_strictly_newer'])

    def test_duplicate_incoming_expected_pair_refuses_across_families(self):
        incoming=copy.deepcopy(self.proof['effects']['incoming'][0])
        incoming.update(name='kernel-hwe',nevra='kernel-hwe-3-1.x86_64',file='packages/1.rpm')
        self.proof['effects']['incoming'].append(incoming)
        addition=copy.deepcopy(self.proof['additions'][0]);addition.update(nevra=incoming['nevra'],file=incoming['file'])
        self.proof['additions'].append(addition)
        with self.assertRaisesRegex(ValueError,'share expected image/module paths'):self.observe()

    def test_repeated_installed_expected_paths_remain_observations_without_retention_claim(self):
        self.installed('kernel-hwe','2-1')
        guard=self.observe()['kernel_path_guard']
        self.assertEqual(guard['observed_kernel_identities_considered'],3)
        self.assertFalse(guard['kernel_retention_policy_satisfied'])

    def test_bad_complete_inventory_hash_count_baseline_or_order_precedes_success(self):
        for key,value in (('entries_sha256','f'*64),('headers',1),('baseline_sha256','f'*64)):
            self.prepare_floor();self.proof['effects']['installed_versions'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.observe()
        self.prepare_floor();self.proof['effects']['installed_versions']['entries'].reverse()
        with self.assertRaises(ValueError):self.observe()

    def test_noarch_and_noncanonical_unrelated_installed_kernel_identity_refuse(self):
        for evr,arch in (('4-1','noarch'),('01:4-1','x86_64'),('4294967296:4-1','x86_64')):
            self.prepare_floor();self.installed('kernel-hwe',evr,arch=arch)
            with self.subTest(evr=evr,arch=arch),self.assertRaises(ValueError):self.observe()

    def test_partial_batch_collision_withholds_the_whole_private_cli_json(self):
        owner=copy.deepcopy(self.proof['effects']['incoming'][0]);owner.update(name='kernel-hwe',nevra='kernel-hwe-2-1.x86_64',file='packages/1.rpm')
        self.proof['effects']['incoming'].append(owner)
        addition=copy.deepcopy(self.proof['additions'][0]);addition.update(nevra=owner['nevra'],file=owner['file']);self.proof['additions'].append(addition)
        result=self.invoke(expected=75);self.assertIn(b'overlap an observed installed identity',result.stderr)

    def test_private_cli_refuses_epoch_collision_without_mutating_the_input(self):
        self.prepare_floor(new='9:2-1');result=self.invoke(expected=75)
        self.assertIn(b'overlap an observed installed identity',result.stderr)

    def test_empty_and_non_kernel_batches_do_not_claim_comparison(self):
        for empty in (False,True):
            self.prepare_floor(name='userland')
            if empty:
                self.proof['effects']['incoming']=[];self.proof['additions']=[];self.proof['rpm_test_performed']=False
            with self.subTest(empty=empty):
                guard=self.observe()['kernel_path_guard'];self.assertEqual(guard['matches'],[])
                self.assertFalse(guard['expected_path_comparison_performed']);self.assertFalse(guard['expected_paths_disjoint'])

    def test_downgrade_and_native_order_controls_cannot_be_bypassed_by_path_check(self):
        self.prepare_floor(new='1-1')
        with self.assertRaisesRegex(ValueError,'downgrade'):self.observe()
        self.prepare_floor();proof=self.namespace['observe'](copy.deepcopy(self.proof))
        proof=self.namespace['version_observe'](proof,lambda:self.compare)
        with self.assertRaises(ValueError):self.namespace['kernel_paths'](proof,lambda:lambda *args:0)

    def test_all_seventeen_policy_authority_flags_remain_false(self):
        result=self.observe()['kernel_path_guard']
        for key in ('installed_headers_authenticated','actual_filesystem_collisions_checked','installed_declared_paths_read',
                    'incoming_declared_paths_read','all_kernel_names_identified','all_kernel_families_supported',
                    'alternate_paths_checked','aliases_hardlinks_checked','kernel_retention_policy_satisfied',
                    'rollback_policy_satisfied','running_kernel_identified','bootability_proven','installation_authorized',
                    'installs_performed','scripts_executed','reboot_authorized','server_ready'):
            self.assertIs(result[key],False)


COLLISION_LIBRARY=floors.FLOOR_LIBRARY
COLLISION_LIBRARY=COLLISION_LIBRARY.replace('void *headerGetAsString(', 'void *oldCollisionIdentity(')
COLLISION_LIBRARY=COLLISION_LIBRARY.replace('const char *rpmteNEVRA(', 'const char *oldCollisionTE(')
COLLISION_LIBRARY+=r'''
void *headerGetAsString(void *h,int tag) {
    if(incoming(h) && setting("kernel_epoch_collision")) {
        if(tag!=5016)abort();return strdup("kernel-9:2-1.x86_64");
    }
    return oldCollisionIdentity(h,tag);
}
const char *rpmteNEVRA(void *element) {
    return setting("kernel_epoch_collision")?"kernel-9:2-1.x86_64":oldCollisionTE(element);
}
'''


class KernelPathPipelineTests(unittest.TestCase):
    temporary_parent=compatibility.admission.protected_model_parent()
    command=floors.IncomingFloorPipelineTests.command
    configure=floors.IncomingFloorPipelineTests.configure
    calls=floors.IncomingFloorPipelineTests.calls
    setUp=floors.IncomingFloorPipelineTests.setUp
    header=floors.IncomingFloorPipelineTests.header
    prepare=floors.IncomingFloorPipelineTests.prepare
    native_calls=floors.IncomingFloorPipelineTests.native_calls
    shell=floors.IncomingFloorPipelineTests.shell
    default_body=floors.IncomingFloorPipelineTests.default_body

    @classmethod
    def setUpClass(cls):
        temporary=tempfile.TemporaryDirectory(prefix='s4-kernel-path-abi-',dir=Path.home()/'.cache')
        cls.addClassCleanup(temporary.cleanup);cls.library=Path(temporary.name)/'librpm-kernel-path-model.so'
        subprocess.run(['cc','-shared','-fPIC','-x','c','-',str(ROOT/'Updates.Tests/rpm_version_model.c'),'-o',str(cls.library)],
                       input=COLLISION_LIBRARY,text=True,capture_output=True,check=True)

    def test_current_install_only_path_comparison_binds_inventory_and_preserves_pointer(self):
        self.prepare(kernel=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        proof=json.loads(self.shell().stdout);guard=proof['kernel_path_guard']
        self.assertEqual(guard['observed_kernel_identities_considered'],2)
        self.assertEqual(guard['matches'][0]['owner']['sha256'],proof['additions'][0]['sha256'])
        self.assertEqual(guard['baseline_sha256'],proof['baseline']['sha256'])
        self.assertTrue(guard['expected_paths_disjoint']);self.assertFalse(guard['actual_filesystem_collisions_checked'])
        self.assertIn('upgrade 0',self.native_calls());self.assertEqual(proof['removals'],[])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'proof':proof,'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'native_calls':self.native_calls(),'real_install_or_boot':False}

    def test_epoch_collision_refuses_after_current_test_with_no_proof_or_pointer_change(self):
        self.prepare(kernel=True,kernel_epoch_collision=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        result=self.shell(expected=75);self.assertEqual(result.stdout,'')
        self.assertIn('kernel expected image/module paths overlap an observed installed identity',result.stderr)
        self.assertIn('run 1',self.native_calls());self.assertIn('upgrade 0',self.native_calls())
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'exit':75,'stdout':result.stdout,'stderr':result.stderr,
                     'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'native_calls':self.native_calls(),'real_install_or_boot':False}

    def test_collision_keeps_automatic_retry_and_blocks_default_finalization(self):
        self.prepare(kernel=True,kernel_epoch_collision=True)
        result=self.shell(self.default_body(),expected=75,timeout=180)
        self.assertIn('kernel expected image/module paths overlap an observed installed identity',result.stderr)
        self.assertTrue((self.root/'state/retry').exists());self.assertFalse((self.root/'state/finished').exists())
        self.assertIn('status=pending',(self.root/'state/components/update-removals').read_text())

    def test_stale_success_does_not_skip_collision_and_fresh_retry_can_recover(self):
        self.prepare(kernel=True);self.shell('s4_reconcile_component update-removals yes')
        self.configure(kernel=True,kernel_epoch_collision=True);self.shell('s4_reconcile_component update-removals yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-removals').read_text())
        self.configure(kernel=True);self.shell('s4_reconcile_component update-removals yes')
        self.assertIn('status=complete',(self.root/'state/components/update-removals').read_text())


if __name__=='__main__':unittest.main()

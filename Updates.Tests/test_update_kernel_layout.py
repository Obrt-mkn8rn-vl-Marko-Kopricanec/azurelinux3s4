import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import test_update_interpreter_paths as paths
import test_update_interpreters as interpreters


class KernelLayoutTests(unittest.TestCase):
    setUpClass = classmethod(interpreters.InterpreterObservationTests.setUpClass.__func__)
    make_proof = interpreters.InterpreterObservationTests.make_proof
    supplied = paths.InterpreterPathTests.supplied
    declaration = paths.InterpreterPathTests.declaration

    def setUp(self):
        paths.InterpreterPathTests.setUp(self)
        self.kernel()

    def kernel(self, name='kernel', evr='2-1.azl3', arch='x86_64'):
        release = evr.split(':')[-1]
        self.supplied([self.declaration('/boot/vmlinuz-' + release, stat.S_IFREG | 0o600),
                       self.declaration('/lib/modules/' + release + '/vmlinuz', stat.S_IFLNK | 0o777,
                                        link='/boot/vmlinuz-' + release)])
        incoming = self.proof['effects']['incoming'][0]
        incoming.update(name=name, nevra=f'{name}-{evr}.{arch}')
        owner = self.proof['namespace_inventory']['incoming'][0]
        owner.update(name=name, nevra=incoming['nevra'])
        self.proof['additions'][0]['nevra'] = incoming['nevra']
        return owner['files']

    def observe(self):
        proof = self.namespace['observe'](copy.deepcopy(self.proof))
        return self.namespace['kernel_layout'](proof)

    def test_image_and_module_alias_bind_same_header_snapshot_and_version_release(self):
        proof = self.observe(); result = proof['kernel_layout']; match = result['matches'][0]
        self.assertEqual(match['declared_release'], '2-1.azl3')
        self.assertEqual(match['owner']['sha256'], self.proof['effects']['incoming'][0]['sha256'])
        self.assertEqual(match['owner']['header_sha256'], self.proof['effects']['incoming'][0]['header_sha256'])
        self.assertEqual(result['namespace_inventory_sha256'], proof['interpreter_path_correspondence']['inventory_sha256'])
        self.assertEqual(match['module_alias']['link'], match['image']['path'])

    def test_supported_family_architecture_profiles_are_explicit(self):
        for name, arches in (('kernel', ('x86_64','aarch64')), ('kernel-hwe', ('x86_64','aarch64')),
                             ('kernel-64k', ('aarch64',))):
            for arch in arches:
                with self.subTest(name=name, arch=arch):
                    self.kernel(name=name,arch=arch)
                    self.assertEqual(self.observe()['kernel_layout']['matches'][0]['architecture'],arch)

    def test_epoch_is_recorded_but_not_inserted_into_physical_release_paths(self):
        self.kernel(evr='9:2-1.azl3'); match=self.observe()['kernel_layout']['matches'][0]
        self.assertEqual(match['epoch'],'9');self.assertEqual(match['declared_release'],'2-1.azl3')
        self.assertFalse(self.observe()['kernel_layout']['kernel_retention_policy_satisfied'])

    def test_unvetted_uki_vm_and_mshv_families_refuse(self):
        for name in ('kernel-uki','kernel-uvm','kernel-mshv'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError,'not been vetted'):
                self.kernel(name=name);self.observe()

    def test_noarch_and_64k_x86_declarations_refuse(self):
        for name,arch in (('kernel','noarch'),('kernel-64k','x86_64')):
            with self.subTest(name=name,arch=arch), self.assertRaisesRegex(ValueError,'architecture'):
                self.kernel(name=name,arch=arch);self.observe()

    def test_noncanonical_and_overflow_epoch_cannot_make_a_layout(self):
        for evr in ('01:2-1.azl3','4294967296:2-1.azl3','x:2-1.azl3'):
            with self.subTest(evr=evr), self.assertRaises(ValueError):
                self.kernel(evr=evr);self.observe()

    def test_missing_or_cross_release_image_refuses(self):
        for mode in ('missing','foreign'):
            self.kernel(); entries=self.proof['namespace_inventory']['incoming'][0]['files']
            if mode=='missing':entries.pop(0);self.proof['namespace_inventory']['files']=1
            else:entries[0]['path']='/boot/vmlinuz-1-1.azl3'
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'missing or inconsistent'):self.observe()

    def test_empty_ghost_linked_directory_and_writable_images_refuse(self):
        for key,value in (('bytes',0),('flags',64),('mode',stat.S_IFDIR|0o700),
                          ('mode',stat.S_IFREG|0o622),('mode',stat.S_IFREG|0o4600)):
            self.kernel();self.proof['namespace_inventory']['incoming'][0]['files'][0][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.observe()
        self.kernel();image=self.proof['namespace_inventory']['incoming'][0]['files'][0]
        image.update(mode=stat.S_IFLNK|0o777,link='/foreign')
        with self.assertRaises(ValueError):self.observe()

    def test_module_alias_must_be_nonghost_link_to_exact_image(self):
        for fields in ({'flags':64},{'mode':stat.S_IFREG|0o600,'link':''},
                       {'link':'../../boot/vmlinuz-2-1.azl3'}, {'link':'/boot/vmlinuz-1-1.azl3'}):
            self.kernel();self.proof['namespace_inventory']['incoming'][0]['files'][1].update(fields)
            with self.subTest(fields=fields),self.assertRaises(ValueError):self.observe()

    def test_ordinary_0777_symlink_permissions_are_not_access_permissions(self):
        match=self.observe()['kernel_layout']['matches'][0]
        self.assertEqual(stat.S_IMODE(match['module_alias']['mode']),0o777)

    def test_extra_direct_image_or_module_release_refuses(self):
        for path in ('/boot/vmlinuz-foreign','/lib/modules/foreign/vmlinuz'):
            self.kernel();self.proof['namespace_inventory']['incoming'][0]['files'].append(self.declaration(path))
            self.proof['namespace_inventory']['files']=3
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'another image/module release'):self.observe()

    def test_duplicate_path_and_owner_hash_fail_before_layout_result(self):
        for bad in ('duplicate','hash'):
            self.kernel();owner=self.proof['namespace_inventory']['incoming'][0]
            if bad=='duplicate':owner['files'].append(owner['files'][0]);self.proof['namespace_inventory']['files']=3
            else:owner['header_sha256']='f'*64
            with self.subTest(bad=bad),self.assertRaises(ValueError):self.observe()

    def test_two_incoming_families_cannot_share_the_pair(self):
        owner=copy.deepcopy(self.proof['effects']['incoming'][0]);owner.update(name='kernel-hwe',nevra='kernel-hwe-2-1.azl3.x86_64',file='packages/1.rpm')
        source=copy.deepcopy(self.proof['namespace_inventory']['incoming'][0]);source.update({k:owner[k] for k in ('name','nevra','file')})
        self.proof['effects']['incoming'].append(owner);self.proof['namespace_inventory']['incoming'].append(source)
        self.proof['additions'].append({k:owner[k] for k in ('file','sha256','bytes','nevra')})
        self.proof['namespace_inventory']['files']=4
        with self.assertRaisesRegex(ValueError,'share an image'):self.observe()

    def test_later_invalid_kernel_withholds_whole_layout(self):
        owner=copy.deepcopy(self.proof['effects']['incoming'][0]);owner.update(name='kernel-hwe',nevra='kernel-hwe-3-1.azl3.x86_64',file='packages/1.rpm')
        source={**{k:owner[k] for k in ('name','nevra','file','sha256','bytes','header_bytes','header_sha256')},'files':[]}
        self.proof['effects']['incoming'].append(owner);self.proof['namespace_inventory']['incoming'].append(source)
        self.proof['additions'].append({k:owner[k] for k in ('file','sha256','bytes','nevra')})
        with self.assertRaisesRegex(ValueError,'missing or inconsistent'):self.observe()

    def test_non_kernel_and_empty_batches_do_not_claim_kernel_validation(self):
        for empty in (False,True):
            self.kernel(name='userland')
            if empty:
                self.proof['effects']['incoming']=[];self.proof['additions']=[]
                self.proof['namespace_inventory']['incoming']=[];self.proof['namespace_inventory']['files']=0
                self.proof['rpm_test_performed']=False
            with self.subTest(empty=empty):
                result=self.observe()['kernel_layout'];self.assertEqual(result['matches'],[])
                self.assertFalse(result['declared_pairs_consistent'])

    def test_all_nineteen_policy_authority_flags_stay_false(self):
        result=self.observe()['kernel_layout']
        flags=('all_kernel_families_supported','all_boot_artifacts_checked','payload_bytes_read','image_format_checked',
               'hmac_verified','modules_complete','installed_baseline_authenticated','running_kernel_identified',
               'bootloader_checked','initramfs_checked','kernel_retention_policy_satisfied','rollback_policy_satisfied',
               'bootability_proven','reboot_authorized','kernel_version_policy_satisfied','installation_authorized',
               'installs_performed','scripts_executed','server_ready')
        for flag in flags:self.assertIs(result[flag],False)


# Finite file/header/library/signature/manager MODEL, not actual kernel RPMs.
KERNEL_LIBRARY=paths.PATH_LIBRARY
for name in ('headerGetAsString','rpmteNEVRA','rpmfiFN','rpmfiFMode','rpmfiFLink','rpmfiFFlags'):
    KERNEL_LIBRARY=KERNEL_LIBRARY.replace(name+'(', 'oldKernel_'+name+'(')
KERNEL_LIBRARY+=r'''
void *headerGetAsString(void *h,int tag) {
    if(tag!=5016) abort();return strdup(incoming(h)?"kernel-2-1.azl3.x86_64":"kernel-1-1.azl3.x86_64");
}
const char *rpmteNEVRA(void *element) { return "kernel-2-1.azl3.x86_64"; }
const char *rpmfiFN(FI *fi) {
    return fi->index ? "/lib/modules/2-1.azl3/vmlinuz" : "/boot/vmlinuz-2-1.azl3";
}
uint16_t rpmfiFMode(FI *fi) { return fi->index?0120777:0100600; }
const char *rpmfiFLink(FI *fi) {
    return fi->index?(setting("wrong_kernel_target")?"/boot/vmlinuz-foreign":"/boot/vmlinuz-2-1.azl3"):"";
}
unsigned rpmfiFFlags(FI *fi) { return setting("ghost_kernel")?64:0; }
'''


class KernelLayoutPipelineTests(unittest.TestCase):
    temporary_parent=paths.InterpreterPathPipelineTests.temporary_parent
    command=paths.InterpreterPathPipelineTests.command
    configure=paths.InterpreterPathPipelineTests.configure
    calls=paths.InterpreterPathPipelineTests.calls
    setUp=paths.InterpreterPathPipelineTests.setUp
    header=paths.InterpreterPathPipelineTests.header
    prepare=paths.InterpreterPathPipelineTests.prepare
    native_calls=paths.InterpreterPathPipelineTests.native_calls
    shell=paths.InterpreterPathPipelineTests.shell

    @classmethod
    def setUpClass(cls):
        temporary=tempfile.TemporaryDirectory(prefix='s4-kernel-layout-abi-',dir=Path.home()/'.cache')
        cls.addClassCleanup(temporary.cleanup);cls.library=Path(temporary.name)/'librpm-kernel-layout-model.so'
        subprocess.run(['cc','-shared','-fPIC','-x','c','-','-o',str(cls.library)],input=KERNEL_LIBRARY,
                       text=True,capture_output=True,check=True)

    def test_current_install_only_kernel_layout_keeps_snapshot_pointer_and_false_authority(self):
        self.prepare(kernel=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        proof=json.loads(self.shell().stdout);result=proof['kernel_layout']
        self.assertEqual(result['kernel_headers_checked'],1);self.assertEqual(result['matches'][0]['declared_release'],'2-1.azl3')
        self.assertEqual(result['matches'][0]['owner']['sha256'],proof['additions'][0]['sha256'])
        self.assertEqual(result['namespace_inventory_sha256'],proof['interpreter_path_correspondence']['inventory_sha256'])
        self.assertFalse(result['bootability_proven']);self.assertFalse(result['installation_authorized'])
        self.assertIn('upgrade 0',self.native_calls());self.assertEqual(proof['removals'],[])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'proof':proof,'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'native_calls':self.native_calls(),'real_install_or_boot':False}

    def test_wrong_module_target_defers_with_specific_reason_and_zero_json(self):
        self.prepare(kernel=True,wrong_kernel_target=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        result=self.shell(expected=75);self.assertEqual(result.stdout,'')
        self.assertIn('kernel image/module alias declarations are missing or inconsistent',result.stderr)
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'exit':75,'stdout':result.stdout,'stderr':result.stderr,
                     'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'real_install_or_boot':False}

    def test_prior_success_never_skips_current_layout_and_retry_recovers(self):
        self.prepare(kernel=True);self.shell('s4_reconcile_component update-interpreters yes')
        self.configure(kernel=True,ghost_kernel=True);self.shell('s4_reconcile_component update-interpreters yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-interpreters').read_text())
        self.configure(kernel=True);self.shell('s4_reconcile_component update-interpreters yes')
        self.assertIn('status=complete',(self.root/'state/components/update-interpreters').read_text())


if __name__=='__main__':unittest.main()

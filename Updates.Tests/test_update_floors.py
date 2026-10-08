import copy
import ctypes as C
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_update_baselines as baselines
import test_update_compatibility as compatibility
import test_update_interpreters as interpreters
import test_update_removals as removals


ROOT = Path(__file__).resolve().parents[1]


class IncomingFloorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = interpreters.emitted('s4_update_removals_program')
        cls.namespace = {'__name__': 'fixture'}
        exec(compile(cls.program, '<actual-incoming-floor-client>', 'exec'), cls.namespace)
        temporary = tempfile.TemporaryDirectory(prefix='s4-floor-comparison-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup)
        cls.library = Path(temporary.name) / 'librpm-floor-model.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', str(ROOT / 'Updates.Tests/rpm_version_model.c'),
                        '-o', str(cls.library)], input=compatibility.LIBRARY, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library))
        cls.lib.rpmvercmp.argtypes = (C.c_char_p, C.c_char_p); cls.lib.rpmvercmp.restype = C.c_int

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='s4-floor-proof-')
        self.addCleanup(temporary.cleanup); self.root = Path(temporary.name)
        self.proof = removals.RemovalGuardTests.make_proof()
        self.script = self.root / 'guard.py'
        self.assertEqual(self.program.count('C.CDLL("librpm.so.9",'), 1)
        self.script.write_text(self.program.replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ','))

    def compare(self, left, right):
        return self.lib.rpmvercmp(left.encode(), right.encode())

    def refresh(self):
        entries = self.proof['effects']['installed_versions']['entries']
        entries.sort(key=lambda row: row['instance'])
        material = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
        baseline = hashlib.sha256(json.dumps([(row['instance'], row['header_sha256']) for row in entries],
                                            separators=(',', ':')).encode()).hexdigest()
        self.proof['baseline'].update(headers=len(entries), sha256=baseline)
        self.proof['effects']['installed_headers_observed'] = len(entries)
        self.proof['effects']['installed_versions'].update(headers=len(entries), baseline_sha256=baseline,
                                                          entries_bytes=len(material), entries_sha256=hashlib.sha256(material).hexdigest())

    def prepare_floor(self, name='kernel', new='3-1', installed=('1-1', '2-1'), arch='x86_64'):
        self.proof = removals.RemovalGuardTests.make_proof(name, arch)
        incoming = self.proof['effects']['incoming'][0]; incoming['nevra'] = name + '-' + new + '.' + arch
        self.proof['additions'][0].update(nevra=incoming['nevra'], install_only=name in self.namespace['KERNELS'])
        self.proof['removals'] = []; self.proof['effects']['removals'] = []
        entries = self.proof['effects']['installed_versions']['entries']
        entries[:] = [{'instance': index+1, 'name': name, 'nevra': name + '-' + value + '.' + arch,
                       'header_bytes': 64, 'header_sha256': hashlib.sha256(str(index).encode()).hexdigest()}
                      for index, value in enumerate(installed)]
        if not entries:
            entries.append({'instance': 1, 'name': 'gpg-pubkey', 'nevra': 'gpg-pubkey-135ce90-66878efc.(none)',
                            'header_bytes': 64, 'header_sha256': 'b' * 64})
        self.refresh()

    def observe(self, factory=None):
        value = self.namespace['observe'](copy.deepcopy(self.proof))
        value = self.namespace['version_observe'](value, lambda: self.compare)
        return self.namespace['floor_observe'](value, factory or (lambda: self.compare))

    def invoke(self, expected=0):
        path = self.root / 'result.json'; data = json.dumps(self.proof).encode(); path.write_bytes(data); path.chmod(0o600)
        result = subprocess.run(['python3', '-I', str(self.script), str(self.root)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stderr.decode())
        self.assertEqual(path.read_bytes(), data)
        if expected: self.assertEqual(result.stdout, b'')
        return result

    def test_current_same_name_replacement_keeps_snapshot_and_installed_maximum_binding(self):
        result = self.observe(); guard = result['incoming_version_guard']; match = guard['matches'][0]
        self.assertEqual(match['maximum_installed']['instance'], 7)
        self.assertEqual(match['maximum_installed']['header_sha256'], 'e' * 64)
        self.assertEqual(match['file'], 'packages/0.rpm'); self.assertEqual(match['sha256'], 'c' * 64)
        self.assertEqual(guard['baseline_sha256'], result['baseline']['sha256'])
        self.assertEqual(guard['inventory_sha256'], result['effects']['installed_versions']['entries_sha256'])
        self.assertFalse(result['replacement_version_guard']['all_incoming_versions_checked'])

    def test_install_only_kernel_must_exceed_newest_of_every_observed_installed_version(self):
        self.prepare_floor(installed=('2-1', '1-1'))
        result = self.observe()['incoming_version_guard']; match = result['matches'][0]
        self.assertEqual(match['maximum_installed']['nevra'], 'kernel-2-1.x86_64')
        self.assertEqual(match['installed_instances_considered'], 2)
        self.assertEqual(result['matched_kernel_floors'], 1)
        self.assertEqual(result['incoming_count'], 1); self.assertTrue(result['matched_incoming_strictly_newer'])

    def test_matching_newest_kernel_downgrade_and_semantic_reinstall_refuse_without_erasure(self):
        for new in ('1-1', '2-1', '02-1'):
            self.prepare_floor(new=new)
            with self.subTest(new=new), self.assertRaisesRegex(ValueError, 'downgrade or version-equivalent'): self.observe()

    def test_all_six_kernel_names_use_the_same_floor_without_claiming_complete_kernel_policy(self):
        for name in self.namespace['KERNELS']:
            self.prepare_floor(name=name)
            with self.subTest(name=name):
                guard = self.observe()['incoming_version_guard']
                self.assertEqual(guard['matched_kernel_floors'], 1)
                self.assertFalse(guard['kernel_version_policy_satisfied'])

    def test_epoch_dominates_and_release_breaks_otherwise_equal_installed_maximum(self):
        for old, new, component in ((('1:2-1', '2:1-1'), '3:1-1', 'epoch'),
                                    (('1-1', '1-2'), '1-3', 'release')):
            self.prepare_floor(installed=old, new=new)
            with self.subTest(component=component):
                match = self.observe()['incoming_version_guard']['matches'][0]
                self.assertEqual(match['maximum_installed']['nevra'], 'kernel-' + old[1] + '.x86_64')
                self.assertEqual(match['comparisons'][-1]['component'], component)

    def test_tilde_caret_and_numeric_segments_require_native_order(self):
        for old, new in (('1.0~rc1', '1.0'), ('1.0', '1.0^git'), ('1.0^git', '1.0.1'), ('1.9', '1.10')):
            self.prepare_floor(installed=(old+'-1',), new=new+'-1')
            with self.subTest(old=old, new=new): self.assertTrue(self.observe()['incoming_version_guard']['matched_incoming_strictly_newer'])

    def test_supported_architectures_and_name_with_hyphens_are_exact(self):
        for arch in ('x86_64', 'aarch64', 'noarch'):
            self.prepare_floor(name='rpm-libs', arch=arch)
            with self.subTest(arch=arch): self.assertEqual(self.observe()['incoming_version_guard']['matches'][0]['architecture'], arch)

    def test_installed_same_name_architecture_transition_refuses_even_without_erase(self):
        self.prepare_floor()
        self.proof['effects']['installed_versions']['entries'][0]['nevra'] = 'kernel-1-1.noarch'; self.refresh()
        with self.assertRaisesRegex(ValueError, 'architecture conflict'): self.observe()

    def test_unrelated_pseudo_key_is_preserved_without_binary_evr_inference(self):
        result = self.observe()['incoming_version_guard']
        self.assertEqual(result['observed_installed_headers'], 2)
        self.assertEqual(result['matched_incoming_count'], 1)

    def test_new_package_names_report_no_installed_floor_not_universal_version_success(self):
        self.prepare_floor(name='new-package', installed=())
        result = self.observe()['incoming_version_guard']
        self.assertEqual(result['matches'], []); self.assertEqual(len(result['without_installed_name']), 1)
        self.assertTrue(result['all_current_incoming_identities_evaluated']); self.assertFalse(result['matched_incoming_strictly_newer'])
        self.assertEqual(result['matched_kernel_floors'], 0); self.assertFalse(result['freshness_proven'])

    def test_empty_incoming_reports_no_package_or_all_incoming_version_success(self):
        self.proof['effects']['incoming'] = self.proof['effects']['removals'] = []
        self.proof['additions'] = self.proof['removals'] = []; self.proof['rpm_test_performed'] = False
        result = self.observe()['incoming_version_guard']
        self.assertFalse(result['all_current_incoming_identities_evaluated']); self.assertFalse(result['matched_incoming_strictly_newer'])
        self.assertEqual(result['incoming_count'], 0); self.assertEqual(result['native_calls'], 36)

    def test_equivalent_installed_maximum_tie_uses_first_instance_deterministically(self):
        self.prepare_floor(installed=('1.01-1', '1.1-1'), new='1:1.1-1')
        self.assertEqual(self.observe()['incoming_version_guard']['matches'][0]['maximum_installed']['instance'], 1)

    def test_inventory_presence_qualification_and_all_false_authority_are_required(self):
        inventory = self.proof['effects']['installed_versions']
        for key, new in (('schema', True), ('complete_observed_header_inventory', False), ('headers', True),
                         ('installation_authorized', True), ('snapshot_atomic', True), ('entries', {})):
            original = inventory[key]; inventory[key] = new
            with self.subTest(key=key), self.assertRaises(ValueError): self.observe()
            inventory[key] = original
        del self.proof['effects']['installed_versions']
        with self.assertRaises(KeyError): self.observe()

    def test_count_size_hash_and_baseline_changes_refuse_complete_inventory(self):
        inventory = self.proof['effects']['installed_versions']
        for key, new in (('headers', 1), ('entries_bytes', 1), ('entries_bytes', True),
                         ('entries_sha256', 'f'*64), ('baseline_sha256', 'f'*64)):
            original = inventory[key]; inventory[key] = new
            with self.subTest(key=key), self.assertRaises(ValueError): self.observe()
            inventory[key] = original

    def test_duplicate_reordered_and_unsupported_installed_entries_refuse(self):
        original = copy.deepcopy(self.proof['effects']['installed_versions']['entries'])
        for entries in (original[::-1], [original[0], original[0]], [{**original[0], 'extra': False}, original[1]]):
            self.proof['effects']['installed_versions']['entries'] = entries
            with self.subTest(entries=entries), self.assertRaises(ValueError): self.observe()

    def test_unsupported_matching_evr_refuses_while_unrelated_declarations_do_not_invent_floor(self):
        self.prepare_floor()
        for old in ('01:1-1', '4294967296:1-1', '1-1.i686'):
            self.proof['effects']['installed_versions']['entries'][0]['nevra'] = 'kernel-' + old
            if '.' not in old: self.proof['effects']['installed_versions']['entries'][0]['nevra'] += '.x86_64'
            self.refresh()
            with self.subTest(old=old), self.assertRaises(ValueError): self.observe()

    def test_actual_removed_record_must_correspond_to_full_installed_inventory(self):
        self.proof['effects']['installed_versions']['entries'][0]['nevra'] = 'systemd-0-1.azl3.x86_64'
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'removal differs'): self.observe()

    def test_native_participation_boolean_constant_or_invalid_result_cannot_certify_floor(self):
        for result in (True, 0, 1, 42):
            with self.subTest(result=result), self.assertRaises(ValueError): self.observe(lambda: lambda *args: result)

    def test_post_control_nonreversible_order_refuses_before_success(self):
        self.prepare_floor()
        calls = 0
        def changed(left, right):
            nonlocal calls
            calls += 1
            return self.compare(left, right) if calls <= 36 else 1
        with self.assertRaisesRegex(ValueError, 'not reversible'): self.observe(lambda: changed)

    def test_maximum_header_count_can_select_a_floor_with_finite_native_call_bound(self):
        self.prepare_floor(installed=('1-1',), new='2-1')
        source = self.proof['effects']['installed_versions']['entries'][0]
        self.proof['effects']['installed_versions']['entries'] = [{**source, 'instance': index} for index in range(1, 32769)]
        self.refresh()
        result = self.observe()['incoming_version_guard']
        self.assertEqual(result['matches'][0]['installed_instances_considered'], 32768)
        self.assertLessEqual(result['native_calls'], 36 + 6*32768)
        self.assertEqual(result['matches'][0]['maximum_installed']['instance'], 1)

    def test_private_cli_binds_three_guard_digests_to_same_captured_bytes(self):
        result = json.loads(self.invoke().stdout); digest = hashlib.sha256((self.root/'result.json').read_bytes()).hexdigest()
        for name in ('removal_guard', 'replacement_version_guard', 'incoming_version_guard'):
            self.assertEqual(result[name]['input_sha256'], digest)

    def test_no_erasure_kernel_downgrade_private_cli_withholds_all_json(self):
        self.prepare_floor(new='1-1')
        result = self.invoke(expected=75)
        self.assertIn(b'incoming floor is a downgrade', result.stderr)

    def test_partial_incoming_batch_failure_withholds_other_successful_floors(self):
        self.prepare_floor()
        new = copy.deepcopy(self.proof['effects']['incoming'][0]); new.update(name='rpm', nevra='rpm-0-1.x86_64', file='packages/1.rpm')
        self.proof['effects']['incoming'].append(new)
        addition = {key:new[key] for key in ('file', 'sha256', 'bytes', 'nevra')}; addition.update(install_only=False, pretrans_present=False)
        self.proof['additions'].append(addition)
        self.proof['effects']['installed_versions']['entries'].append({'instance': 9, 'name': 'rpm', 'nevra': 'rpm-1-1.x86_64',
                                                                      'header_bytes': 64, 'header_sha256': 'f'*64})
        self.refresh(); self.invoke(expected=75)

    def test_all_policy_authority_flags_remain_false_after_success(self):
        result = self.observe()['incoming_version_guard']
        for flag in ('installed_baseline_authenticated', 'native_library_identity_authenticated', 'kernel_version_policy_satisfied',
                     'package_continuity_proven', 'freshness_proven', 'anti_rollback_proven', 'removal_policy_satisfied',
                     'rollback_policy_satisfied', 'installation_authorized', 'installs_performed', 'scripts_executed', 'server_ready'):
            self.assertIs(result[flag], False)


# Explicit C ABI delivery MODEL: current TEST observes two scriptless installed
# kernel versions plus a key. Incoming is install-only and has no erase element.
FLOOR_LIBRARY = baselines.BASELINE_LIBRARY
for old, new in (('const char *baselineName(', 'const char *floorOldName('),
                 ('const char *headerGetString(', 'const char *floorOldString('),
                 ('void *headerGetAsString(', 'void *floorOldAsString('),
                 ('const char *rpmteNEVRA(', 'const char *floorOldNEVRA(')):
    FLOOR_LIBRARY = FLOOR_LIBRARY.replace(old, new)
FLOOR_LIBRARY = 'const char *baselineName(void *);\n' + FLOOR_LIBRARY
FLOOR_LIBRARY += r'''
const char *baselineName(void *h) { return !incoming(h) && ((TS*)h)->iteration==2 ? "gpg-pubkey" : "kernel"; }
const char *headerGetString(void *h,int tag) { return tag==1000 ? baselineName(h) : floorOldString(h,tag); }
void *headerGetAsString(void *h,int tag) {
    if(tag!=5016) abort();
    if(incoming(h)) return strdup(setting("floor_old") ? "kernel-1-1.x86_64" : "kernel-3-1.x86_64");
    if(((TS*)h)->iteration==2) return strdup("gpg-pubkey-135ce90-66878efc.(none)");
    return strdup(((TS*)h)->iteration==3 ? "kernel-2-1.x86_64" : "kernel-1-1.x86_64");
}
const char *rpmteNEVRA(void *element) { return setting("floor_old") ? "kernel-1-1.x86_64" : "kernel-3-1.x86_64"; }
'''


class IncomingFloorPipelineTests(unittest.TestCase):
    command = compatibility.UpdateCompatibilityTests.command
    configure = compatibility.UpdateCompatibilityTests.configure
    calls = compatibility.UpdateCompatibilityTests.calls
    setUp = compatibility.UpdateCompatibilityTests.setUp
    header = compatibility.UpdateCompatibilityTests.header
    prepare = compatibility.UpdateCompatibilityTests.prepare
    native_calls = compatibility.UpdateCompatibilityTests.native_calls
    shell = removals.UpdateRemovalIntegrationTests.shell
    default_body = removals.UpdateRemovalIntegrationTests.default_body

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-floor-native-model-', dir=Path.home()/'.cache')
        cls.addClassCleanup(temporary.cleanup); cls.library = Path(temporary.name)/'librpm-floor-kernel-model.so'
        subprocess.run(['cc','-shared','-fPIC','-x','c','-','-o',str(cls.library)],
                       input=FLOOR_LIBRARY+(ROOT/'Updates.Tests/rpm_version_model.c').read_text(),
                       text=True,capture_output=True,check=True)

    def test_fresh_current_install_only_kernel_floor_preserves_pointer_and_cleans_snapshots(self):
        self.prepare(kernel=True); pointer=(self.root/'state/updates/current.json').read_bytes()
        proof=json.loads(self.shell().stdout); floor=proof['incoming_version_guard']
        self.assertEqual(proof['removals'], []); self.assertEqual(floor['matched_kernel_floors'],1)
        match=floor['matches'][0]; self.assertEqual(match['maximum_installed']['instance'],3)
        self.assertEqual(match['maximum_installed']['nevra'],'kernel-2-1.x86_64')
        self.assertEqual(match['installed_instances_considered'],2)
        self.assertEqual(match['sha256'],proof['additions'][0]['sha256'])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.assertEqual(list((self.root/'run').glob('update-check.*')),[])
        self.assertTrue(proof['additions'][0]['install_only']); self.assertFalse(proof['installation_authorized'])
        self.record={'scope':'CURRENT store/hash/admission-client/TEST/guards over explicit three-header C ABI/kernel MODEL; not genuine RPM vendor database/signature/native runtime',
                     'proof':proof,'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'native_calls':self.native_calls(),'real_installs_or_scripts':False}

    def test_no_erase_kernel_downgrade_defers_without_partial_proof_or_pointer_change(self):
        self.prepare(kernel=True,floor_old=True); pointer=(self.root/'state/updates/current.json').read_bytes()
        result=self.shell(expected=75)
        self.assertEqual(result.stdout,''); self.assertIn('incoming floor is a downgrade',result.stderr)
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.assertEqual(list((self.root/'run').glob('update-check.*')),[])
        self.record={'scope':'Same explicit kernel C ABI MODEL with older incoming declaration; no erased instance',
                     'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'no_forwarded_proof':True,
                     'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'real_installs_or_scripts':False}

    def test_prior_success_cannot_skip_current_floor_and_fresh_retry_can_recover(self):
        self.prepare(kernel=True); self.shell('s4_reconcile_component update-removals yes')
        self.configure(kernel=True,floor_old=True)
        self.shell('s4_reconcile_component update-removals yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-removals').read_text())
        self.configure(kernel=True); self.shell('s4_reconcile_component update-removals yes')
        self.assertIn('status=complete',(self.root/'state/components/update-removals').read_text())

    def test_automatic_default_finalization_stays_pending_when_current_kernel_floor_fails(self):
        self.prepare(kernel=True,floor_old=True)
        self.shell(self.default_body(),expected=75,timeout=180)
        self.assertTrue((self.root/'state/retry').exists()); self.assertFalse((self.root/'state/finished').exists())
        self.assertIn('status=pending',(self.root/'state/components/update-removals').read_text())

    def test_failure_or_changed_context_precedes_floor_success(self):
        self.prepare(kernel=True)
        for flag, reason in (('changed_baseline','installed header context changed'),
                             ('run_failure','native TEST transaction rejected'),
                             ('header_failure','native signed snapshot header read failed'),
                             ('script_callback','native TEST did not consume and close')):
            self.configure(kernel=True,**{flag:True})
            with self.subTest(flag=flag):
                result=self.shell(expected=75)
                self.assertEqual(result.stdout,''); self.assertIn(reason,result.stderr)

    def test_empty_batch_and_backoff_do_not_claim_or_attempt_kernel_version_success(self):
        self.prepare(empty=True); result=json.loads(self.shell().stdout)
        self.assertFalse(result['rpm_test_performed']); self.assertEqual(result['incoming_version_guard']['matched_kernel_floors'],0)
        self.assertFalse(result['incoming_version_guard']['all_current_incoming_identities_evaluated'])
        before=self.native_calls()
        self.shell('s4_write_state update-removals pending 1 1000030 75; s4_reconcile_component update-removals no',expected=75)
        self.assertEqual(self.native_calls(),before)


if __name__ == '__main__': unittest.main()

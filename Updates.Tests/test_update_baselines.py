import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_compatibility as compatibility
import test_update_effects as effects
import test_update_interpreters as interpreters
import test_update_staging as staging


ROOT = Path(__file__).resolve().parents[1]


class InstalledVersionInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = interpreters.emitted('s4_rpm_effects_program')
        cls.namespace = {}
        exec(compile(cls.program, '<actual-baseline-projection>', 'exec'), cls.namespace)

    @staticmethod
    def observations():
        return {
            9: {'instance': 9, 'name': 'kernel', 'nevra': 'kernel-6.6.10-1.azl3.x86_64',
                'header_bytes': 44, 'header_sha256': 'b' * 64, 'tags': []},
            3: {'instance': 3, 'name': 'gpg-pubkey', 'nevra': 'gpg-pubkey-135ce90-66878efc.(none)',
                'header_bytes': 32, 'header_sha256': 'a' * 64, 'tags': []},
            12: {'instance': 12, 'name': 'kernel', 'nevra': 'kernel-6.6.12-1.azl3.x86_64',
                 'header_bytes': 46, 'header_sha256': 'c' * 64, 'tags': [{'not_projected': 'opaque body'}]},
        }

    def baseline(self, values):
        pairs = [(key, value['header_sha256']) for key, value in sorted(values.items())]
        return {'headers': len(values), 'sha256': hashlib.sha256(json.dumps(pairs, separators=(',', ':')).encode()).hexdigest()}

    def inventory(self, values=None, expected=None):
        values = self.observations() if values is None else values
        return self.namespace['installed_version_inventory'](values, expected or self.baseline(values))

    def test_scriptless_kernel_and_pseudo_key_headers_are_included_without_semantic_inference(self):
        value = self.inventory()
        self.assertEqual([entry['instance'] for entry in value['entries']], [3, 9, 12])
        self.assertEqual([entry['name'] for entry in value['entries']], ['gpg-pubkey', 'kernel', 'kernel'])
        self.assertEqual(value['headers'], 3)
        self.assertTrue(value['complete_observed_header_inventory'])
        self.assertNotIn('tags', value['entries'][2])
        self.assertNotIn('opaque body', json.dumps(value))
        for flag in ('installed_headers_authenticated', 'identity_fields_independently_authenticated', 'snapshot_atomic',
                     'all_incoming_versions_checked', 'kernel_version_policy_satisfied', 'freshness_proven',
                     'anti_rollback_proven', 'installation_authorized', 'server_ready'):
            self.assertIs(value[flag], False)

    def test_entire_compact_serialization_bytes_and_both_inventory_baseline_hashes_correspond(self):
        values = self.observations(); value = self.inventory(values)
        data = json.dumps(value['entries'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(value['entries_bytes'], len(data))
        self.assertEqual(value['entries_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(value['baseline_sha256'], self.baseline(values)['sha256'])

    def test_input_order_does_not_change_inventory_or_hash(self):
        values = self.observations()
        self.assertEqual(self.inventory(values), self.inventory(dict(reversed(list(values.items())))))

    def test_projection_does_not_mutate_observations_or_include_unlisted_metadata(self):
        values = self.observations(); before = copy.deepcopy(values)
        result = self.inventory(values)
        self.assertEqual(values, before)
        self.assertEqual(set(result['entries'][0]), set(self.namespace['INSTALLED_VERSION_FIELDS']))
        self.assertIsNot(result['entries'][0], values[3])

    def test_count_mismatch_missing_or_forged_baseline_refuses(self):
        values = self.observations()
        for expected in ({}, {'headers': True, 'sha256': 'a' * 64}, {'headers': 2, 'sha256': 'a' * 64},
                         {'headers': 3, 'sha256': '0' * 64}, {'headers': 3, 'sha256': 'invalid'}):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                self.namespace['installed_version_inventory'](values, expected)

    def test_empty_excessive_wrong_type_or_invalid_instance_maps_refuse(self):
        for values in ({}, [], {True: {}}, {0: {}}, {2**32: {}}, {'1': {}}, {1: None}):
            with self.subTest(values=values), self.assertRaises((ValueError, KeyError)):
                self.namespace['installed_version_inventory'](values, {'headers': len(values), 'sha256': 'a' * 64})
        values = {number: {} for number in range(1, 32770)}
        with self.assertRaises(ValueError):
            self.namespace['installed_version_inventory'](values, {'headers': len(values), 'sha256': 'a' * 64})

    def test_changed_instance_or_export_digest_cannot_match_original_baseline(self):
        values = self.observations(); original = self.baseline(values)
        altered = copy.deepcopy(values); altered[9]['header_sha256'] = 'd' * 64
        with self.assertRaises(ValueError): self.inventory(altered, original)
        altered = copy.deepcopy(values); altered[19] = altered.pop(9); altered[19]['instance'] = 19
        with self.assertRaises(ValueError): self.inventory(altered, original)

    def test_wrong_record_fields_types_bounds_controls_or_name_correspondence_refuse(self):
        for key, new in (('instance', True), ('instance', 99), ('name', '../kernel'), ('name', 'x' * 257),
                         ('nevra', 'foreign-1-1.x86_64'), ('nevra', 'kernel-1\n-1.x86_64'),
                         ('nevra', 'kernel-1\u2028-1.x86_64'), ('nevra', 'kernel-' + 'x' * 1024),
                         ('header_bytes', True), ('header_bytes', 7), ('header_bytes', 8*1024*1024+1),
                         ('header_sha256', 'A' * 64)):
            values = self.observations(); values[9][key] = new
            with self.subTest(key=key, new=new), self.assertRaises(ValueError): self.inventory(values)

    def test_maximum_supported_header_count_is_complete_without_sort_or_hash_loss(self):
        source = self.observations()[9]
        values = {number: {**source, 'instance': number} for number in range(1, 32769)}
        result = self.inventory(values)
        self.assertEqual(result['headers'], 32768)
        self.assertEqual(result['entries'][0]['instance'], 1)
        self.assertEqual(result['entries'][-1]['instance'], 32768)
        self.assertLess(result['entries_bytes'], self.namespace['INSTALLED_VERSION_LIMIT'])

    def test_aggregate_serialization_bound_refuses_without_truncated_success(self):
        source = self.observations()[9]
        source.update(name='n' * 255, nevra='n' * 255 + '-' + 'v' * 767)
        values = {number: {**source, 'instance': number} for number in range(1, 8001)}
        with self.assertRaisesRegex(ValueError, 'inventory exceeds'):
            self.inventory(values)

    def test_exact_serialization_limit_and_one_byte_beyond_have_distinct_results(self):
        value = self.inventory(); length = value['entries_bytes']
        with patch.dict(self.namespace, INSTALLED_VERSION_LIMIT=length):
            self.assertEqual(self.inventory(), value)
        with patch.dict(self.namespace, INSTALLED_VERSION_LIMIT=length-1):
            with self.assertRaisesRegex(ValueError, 'inventory exceeds'): self.inventory()


# Public ABI/error-delivery MODEL. Three installed instances, two non-script
# owners, no genuine signatures/database/vendor runtime semantics.
BASELINE_LIBRARY = effects.LIBRARY
for old, new in (('void *rpmdbNextIterator(', 'void *baselineOldNextIterator('),
                 ('unsigned rpmdbGetIteratorOffset(', 'unsigned baselineOldOffset('),
                 ('const char *headerGetString(', 'const char *baselineOldString('),
                 ('void *headerGetAsString(', 'void *baselineOldAsString('),
                 ('void *headerExport(', 'void *baselineOldExport(')):
    BASELINE_LIBRARY = BASELINE_LIBRARY.replace(old, new)
BASELINE_LIBRARY += r'''
void *rpmdbNextIterator(TS *ts) { return ts->iteration++ < 3 ? ts : NULL; }
unsigned rpmdbGetIteratorOffset(TS *ts) {
    return setting("baseline_duplicate_instance") ? 1 : setting("baseline_zero_instance") ? 0 : ts->iteration;
}
const char *baselineName(void *header) {
    if (incoming(header)) return "userland";
    return ((TS *)header)->iteration == 2 ? "gpg-pubkey" : ((TS *)header)->iteration == 3 ? "kernel" : "userland";
}
const char *headerGetString(void *h,int tag) { return tag==1000 ? baselineName(h) : baselineOldString(h,tag); }
void *headerGetAsString(void *h,int tag) {
    if (tag!=5016) abort();
    if (!incoming(h) && ((TS *)h)->iteration==2) return strdup("gpg-pubkey-135ce90-66878efc.(none)");
    if (!incoming(h) && ((TS *)h)->iteration==3) return strdup("kernel-6.6.10-1.azl3.x86_64");
    return baselineOldAsString(h,tag);
}
void *headerExport(void *h,unsigned *size) {
    if (incoming(h) || ((TS *)h)->iteration==1) return baselineOldExport(h,size);
    const char *name=baselineName(h); *size=24+strlen(name)+1;
    unsigned char *out=calloc(1,*size); uint32_t fields[]={1,strlen(name)+1,1000,6,0,1};
    for(int i=0;i<6;i++) { uint32_t value=htonl(fields[i]); memcpy(out+i*4,&value,4); }
    memcpy(out+24,name,strlen(name)+1); return out;
}
'''


class InstalledVersionPipelineTests(unittest.TestCase):
    command = compatibility.UpdateCompatibilityTests.command
    configure = compatibility.UpdateCompatibilityTests.configure
    calls = compatibility.UpdateCompatibilityTests.calls
    setUp = compatibility.UpdateCompatibilityTests.setUp
    header = compatibility.UpdateCompatibilityTests.header
    prepare = compatibility.UpdateCompatibilityTests.prepare
    native_calls = compatibility.UpdateCompatibilityTests.native_calls

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-baseline-abi-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup)
        cls.library = Path(temporary.name) / 'librpm-baseline-model.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=BASELINE_LIBRARY, text=True, capture_output=True, check=True)

    def shell(self, body='s4_check_update_effects', expected=0, timeout=45):
        return staging.UpdateStagingTests.shell(self, body, expected, timeout)

    def test_fresh_test_includes_non_script_key_and_kernel_headers_with_exact_baseline_hash(self):
        self.prepare(userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout); inventory = proof['effects']['installed_versions']
        self.assertEqual(inventory['headers'], proof['baseline']['headers'])
        self.assertEqual(inventory['headers'], 3)
        self.assertEqual([row['instance'] for row in inventory['entries']], [1, 2, 3])
        self.assertEqual([row['name'] for row in inventory['entries']], ['userland', 'gpg-pubkey', 'kernel'])
        self.assertEqual(len(proof['effects']['installed_script_owners']), 1)
        material = json.dumps(inventory['entries'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(inventory['entries_bytes'], len(material))
        self.assertEqual(inventory['entries_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(inventory['baseline_sha256'], proof['baseline']['sha256'])
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertFalse(proof['installation_authorized']); self.assertFalse(inventory['all_incoming_versions_checked'])
        self.assertEqual(list((self.root / 'run').glob('update-check.*')), [])
        self.record = {'scope': 'Actual current client/store/hash/native ABI dispatch with explicit prior signature/manager/'
                               'read-only/ownership deliveries and THREE-instance C MODEL; not vendor RPM proof',
                       'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
                       'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
                       'ordinary_cleanup_verified': True, 'native_calls': self.native_calls(),
                       'native_library_identity_authenticated': False, 'real_installs_or_scripts': False}

    def test_duplicate_or_zero_native_instance_cannot_publish_inventory(self):
        self.prepare(userland_removal=True)
        for flag in ('baseline_duplicate_instance', 'baseline_zero_instance'):
            with self.subTest(flag=flag):
                self.configure(userland_removal=True, **{flag: True})
                result = self.shell(expected=75)
                self.assertEqual(result.stdout, '')
                self.assertIn('installed instance', result.stderr)

    def test_changed_installed_header_context_refuses_before_complete_inventory(self):
        self.prepare(userland_removal=True, changed_baseline=True)
        result = self.shell(expected=75)
        self.assertEqual(result.stdout, '')
        self.assertIn('context changed', result.stderr)

    def test_empty_incoming_batch_still_reports_all_installed_headers_without_package_test_claim(self):
        self.prepare(empty=True)
        proof = json.loads(self.shell().stdout)
        self.assertFalse(proof['rpm_test_performed'])
        self.assertEqual(proof['effects']['installed_versions']['headers'], 3)
        self.assertFalse(proof['effects']['installed_versions']['all_incoming_versions_checked'])
        self.record = {'scope': 'Empty incoming batch over THREE installed C-model headers; no package TEST claim',
                       'proof': proof, 'native_library_identity_authenticated': False, 'real_installs_or_scripts': False}

    def test_bad_current_inventory_cannot_reuse_prior_component_success(self):
        self.prepare(userland_removal=True)
        self.shell('s4_reconcile_component update-effects yes')
        self.configure(userland_removal=True, baseline_duplicate_instance=True)
        self.shell('s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())


if __name__ == '__main__': unittest.main()

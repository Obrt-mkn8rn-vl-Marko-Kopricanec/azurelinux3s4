import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

import test_update_compatibility as compatibility
import test_update_staging as staging


SOURCE = Path(__file__).resolve().parents[1] / 'azurelinux3s4.sh'


def exported(entries):
    """Network-order native export fixture, never an authenticated RPM."""
    indexes, data = [], bytearray()
    for tag, kind, values in entries:
        if kind == 4:
            data.extend(b'\0' * (-len(data) % 4))
            encoded = struct.pack('>' + 'I' * len(values), *values)
        else:
            encoded = b''.join(value + b'\0' for value in values)
        indexes.append(struct.pack('>IIII', tag, kind, len(data), len(values)))
        data.extend(encoded)
    return struct.pack('>II', len(indexes), len(data)) + b''.join(indexes) + data


class EffectsDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(['bash', '-c', 'source "$1"; s4_rpm_effects_program', 'fixture', str(SOURCE)],
                                capture_output=True, text=True, check=True)
        cls.program = result.stdout
        cls.namespace = {}
        exec(compile(result.stdout, '<production-effects-decoder>', 'exec'), cls.namespace)

    def audit(self, entries):
        return self.namespace['audit_header'](exported(entries))

    def test_all_seven_ordinary_script_families_and_interpreter_only_are_observed(self):
        tags = self.namespace['EFFECT_TAGS']
        entries = [(tag, kind, [b'/bin/sh'] if disclose and kind == 8 else
                    [0] if kind == 4 else [b'body']) for tag, (_, kind, disclose) in tags.items()
                   if tag in (1023, 1085, 5020, 1024, 1086, 5021, 1025, 1087, 5022,
                              1026, 1088, 5023, 1151, 1153, 5024, 1152, 1154, 5025,
                              1079, 1091, 5026)]
        result = self.audit(entries)
        self.assertEqual(len(result['tags']), 21)
        self.assertEqual(self.audit([(1086, 8, [b'/usr/sbin/ldconfig'])])['tags'][0]['values'],
                         ['/usr/sbin/ldconfig'])

    def test_all_three_trigger_families_preserve_bodies_conditions_flags_indexes_priorities(self):
        entries = [(tag, kind, [7, 11] if kind == 4 else [b'a', b'b'])
                   for tag, (name, kind, _) in self.namespace['EFFECT_TAGS'].items()
                   if name.startswith(('trigger_', 'filetrigger_', 'transfiletrigger_'))]
        result = self.audit(entries)
        self.assertEqual(len(result['tags']), 23)
        self.assertTrue(all(value['count'] == 2 for value in result['tags']))
        self.assertEqual({value['name'] for value in result['tags'] if value['name'].endswith('_priorities')},
                         {'filetrigger_priorities', 'transfiletrigger_priorities'})

    def test_body_bytes_are_hashed_without_decoding_or_evaluating(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'must-not-exist'
            body = b'\xff$(touch ' + str(target).encode() + b'); %{lua:os.execute("false")}'
            result = self.audit([(1023, 6, [body])])
            self.assertEqual(result['tags'][0]['values'], [{'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}])
            self.assertNotIn('touch', json.dumps(result))
            self.assertFalse(target.exists())

    def test_lua_arguments_and_opaque_flags_remain_inventory(self):
        result = self.audit([(1153, 8, [b'<lua>', b'argument']), (5024, 4, [0xffffffff])])
        self.assertEqual(result['tags'][0]['values'], ['<lua>', 'argument'])
        self.assertEqual(result['tags'][1]['values'], [0xffffffff])

    def test_native_ordinary_single_string_interpreters_and_argv_arrays_are_supported(self):
        tags = (1085, 1086, 1087, 1088, 1091, 1153, 1154)
        result = self.audit([(tag, 6, [b'/sbin/ldconfig']) for tag in tags])
        self.assertEqual(len(result['tags']), 7)
        self.assertTrue(all(value['type'] == 6 and value['count'] == 1 for value in result['tags']))
        self.assertTrue(all(value['values'] == ['/sbin/ldconfig'] for value in result['tags']))
        for entry in ((1086, 6, [b'/bin/sh', b'-e']), (1086, 4, [1]), (1092, 6, [b'/bin/sh'])):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.audit([entry])

    def test_export_and_encoded_tag_digests_bind_exact_bytes(self):
        data = exported([(1023, 6, [b'echo one']), (1085, 8, [b'/bin/sh', b'-e'])])
        result = self.namespace['audit_header'](data)
        self.assertEqual(result['header_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['tags'][0]['sha256'], hashlib.sha256(b'echo one\0').hexdigest())
        self.assertNotEqual(result['header_sha256'], self.audit([(1023, 6, [b'echo two'])])['header_sha256'])

    def test_header_without_script_tags_reports_no_declared_effects(self):
        self.assertEqual(self.audit([(1000, 6, [b'package'])])['tags'], [])

    def test_short_truncated_overlong_and_inconsistent_exports_refuse(self):
        data = exported([(1023, 6, [b'body'])])
        for malformed in (b'1234567', data[:-1], data + b'x', struct.pack('>II', 65537, 0),
                          struct.pack('>II', 0, 0), b'x' * (8 * 1024 * 1024 + 1)):
            with self.subTest(length=len(malformed)), self.assertRaises(ValueError):
                self.namespace['audit_header'](malformed)

    def test_duplicate_declared_script_tag_refuses(self):
        with self.assertRaises(ValueError):
            self.audit([(1023, 6, [b'a']), (1023, 6, [b'b'])])

    def test_wrong_declared_types_empty_counts_and_scalar_arrays_refuse(self):
        for entry in ((1023, 8, [b'a']), (1065, 6, [b'a']), (5020, 4, [1, 2]),
                      (1023, 6, [b'a', b'b']), (1085, 8, []), (5020, 8, [b'0'])):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.audit([entry])

    def test_declared_array_count_bound_is_enforced(self):
        with self.assertRaises(ValueError):
            self.audit([(1065, 8, [b''] * 4097)])

    def test_invalid_offsets_and_unaligned_or_truncated_integer_arrays_refuse(self):
        original = bytearray(exported([(5020, 4, [0])]))
        for field, value in ((16, 4), (16, 1), (20, 4096)):
            malformed = original.copy()
            struct.pack_into('>I', malformed, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.namespace['audit_header'](malformed)

    def test_unterminated_strings_and_interpreter_length_or_utf8_refuse(self):
        data = bytearray(exported([(1023, 6, [b'body'])])); data[-1] = 120
        with self.assertRaises(ValueError):
            self.namespace['audit_header'](data)
        for value in (b'x' * 4097, b'\xff'):
            with self.subTest(length=len(value)), self.assertRaises((ValueError, UnicodeError)):
                self.audit([(1085, 8, [value])])

    def test_single_body_size_is_bounded(self):
        with self.assertRaises(ValueError):
            self.audit([(1023, 6, [b'x' * (1024 * 1024 + 1)])])


# Only these additions extend the original disposable C ABI delivery. They
# serialize real-layout fixtures; they do not implement RPM semantics/signatures.
LIBRARY = compatibility.LIBRARY.replace('void *headerExport(', 'void *fixtureOldExport(')
LIBRARY = LIBRARY.replace('const char *headerGetString(', 'const char *fixtureOldString(')
LIBRARY = LIBRARY.replace('const char *rpmteNEVRA(', 'const char *fixtureOldNEVRA(')
LIBRARY = LIBRARY.replace('const char *rpmteN(', 'const char *fixtureOldName(')
LIBRARY = LIBRARY.replace('int rpmtsNElements(', 'int fixtureOldNElements(')
LIBRARY = LIBRARY.replace('int rpmteType(', 'int fixtureOldType(')
LIBRARY = LIBRARY.replace('void *rpmdbNextIterator(', 'void *fixtureOldNextIterator(')
LIBRARY = LIBRARY.replace('unsigned rpmdbGetIteratorOffset(', 'unsigned fixtureOldIteratorOffset(')
LIBRARY += r'''
#include <arpa/inet.h>
static int incoming(void *h) { return *(int *)h==1; }
int rpmtsNElements(TS *ts) { return setting("duplicate_removal") ? ts->n+2 : fixtureOldNElements(ts); }
int rpmteType(void *element) { return setting("duplicate_removal") ? ((uintptr_t)element>=2 ? 2 : 1) : fixtureOldType(element); }
void *rpmdbNextIterator(TS *ts) {
    if(setting("effects_large_metadata")) return ts->iteration++ < 400 ? ts : NULL;
    return fixtureOldNextIterator(ts);
}
unsigned rpmdbGetIteratorOffset(TS *ts) { return setting("effects_large_metadata") ? ts->iteration : fixtureOldIteratorOffset(ts); }
const char *headerGetString(void *h,int tag) {
    if(tag==1000 && !incoming(h) && setting("installed_other")) return "other";
    return fixtureOldString(h,tag);
}
void *headerGetAsString(void *h,int tag) {
    if(tag!=5016) abort();
    return strdup(incoming(h) ? (setting("incoming_identity_failure") ? "foreign-1-1.x86_64" : "userland-1-1.x86_64") :
        setting("installed_other") ? "other-0-1.x86_64" : "userland-0-1.x86_64");
}
const char *rpmteNEVRA(void *element) {
    if((uintptr_t)element>=2) return setting("removal_identity_failure") ? "foreign-0-1.x86_64" :
        setting("installed_other") ? "other-0-1.x86_64" : "userland-0-1.x86_64";
    return "userland-1-1.x86_64";
}
const char *rpmteN(void *element) {
    if((uintptr_t)element==2 && setting("removal_name_failure")) return "foreign";
    if((uintptr_t)element==2 && setting("installed_other")) return "other";
    return fixtureOldName(element);
}
unsigned rpmteDBInstance(void *element) { record("instance",1); return setting("removal_instance_failure") ? 999 : 1; }
void *headerExport(void *h,unsigned *size) {
    if(setting("effects_large_metadata")) {
        *size=24+4096*4; unsigned char *result=malloc(*size); memset(result,255,*size);
        uint32_t fields[]={1,4096*4,5027,4,0,4096};
        for(int i=0;i<6;i++) { uint32_t value=htonl(fields[i]); memcpy(result+i*4,&value,4); }
        return result;
    }
    uint32_t tag=incoming(h)?1023:5076,kind=incoming(h)?6:8;
    if(setting("effects_wrong_type")) kind=4;
    const char *body=ran && setting("changed_baseline") ? "changed" : "echo fixture-no-execution";
    *size=24+strlen(body)+1;
    unsigned char *result=calloc(1,*size); uint32_t fields[]={1,strlen(body)+1,tag,kind,0,1};
    for(int i=0;i<6;i++) { uint32_t value=htonl(fields[i]); memcpy(result+i*4,&value,4); }
    memcpy(result+24,body,strlen(body)+1); return result;
}
'''


class UpdateEffectsTests(unittest.TestCase):
    command = compatibility.UpdateCompatibilityTests.command
    configure = compatibility.UpdateCompatibilityTests.configure
    calls = compatibility.UpdateCompatibilityTests.calls
    setUp = compatibility.UpdateCompatibilityTests.setUp
    header = compatibility.UpdateCompatibilityTests.header
    prepare = compatibility.UpdateCompatibilityTests.prepare
    native_calls = compatibility.UpdateCompatibilityTests.native_calls

    @classmethod
    def setUpClass(cls):
        cls.temporary_library = tempfile.TemporaryDirectory(prefix='azurelinux3s4-effects-', dir=Path.home() / '.cache')
        cls.addClassCleanup(cls.temporary_library.cleanup)
        cls.library = Path(cls.temporary_library.name) / 'librpm-effects.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=LIBRARY, text=True, capture_output=True, check=True)

    def shell(self, body='s4_check_update_effects', expected=0, timeout=45):
        return staging.UpdateStagingTests.shell(self, body, expected, timeout)

    def test_incoming_and_installed_trigger_owners_are_bound_to_observed_headers(self):
        self.prepare(userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = json.loads(self.shell().stdout)
        audit = result['effects']
        self.assertEqual(audit['installed_headers_observed'], result['baseline']['headers'])
        self.assertEqual(audit['incoming'][0]['sha256'], result['additions'][0]['sha256'])
        self.assertEqual(audit['incoming'][0]['tags'][0]['name'], 'prein_body')
        self.assertEqual(audit['installed_script_owners'][0]['tags'][0]['name'], 'transfiletrigger_bodies')
        self.assertEqual(audit['removals'][0]['instance'], 1)
        self.assertEqual(audit['removals'][0]['classification'], 'same-name-replacement')
        self.assertEqual(audit['removals'][0]['nevra'], result['removals'][0])
        for name in ('installed_headers_authenticated', 'trigger_selection_complete', 'script_execution_plan_complete',
                     'script_policy_satisfied', 'removal_policy_satisfied', 'rollback_policy_satisfied'):
            self.assertIs(audit[name], False)
        for name in ('installs_performed', 'scripts_executed', 'installation_authorized', 'storage_capacity_checked', 'freshness_proven'):
            self.assertIs(result[name], False)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertIn('instance 1', self.native_calls())
        self.assertIn('flags 149', self.native_calls())

    def test_other_named_removal_is_reported_without_satisfying_policy(self):
        self.prepare(userland_removal=True, installed_other=True)
        audit = json.loads(self.shell().stdout)['effects']
        self.assertEqual(audit['removals'][0]['classification'], 'other-removal')
        self.assertFalse(audit['removal_policy_satisfied'])

    def test_missing_wrong_instance_name_or_identity_refuses_before_run(self):
        self.prepare(userland_removal=True)
        for flag in ('removal_instance_failure', 'removal_name_failure', 'removal_identity_failure'):
            with self.subTest(flag=flag):
                self.configure(userland_removal=True, **{flag: True})
                result = self.shell(expected=75)
                self.assertEqual(result.stdout, '')
        self.assertNotIn('run 1', self.native_calls())

    def test_script_callback_and_installed_context_change_cannot_publish_audit(self):
        self.prepare()
        for flag in ('script_callback', 'changed_baseline'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.assertEqual(self.shell(expected=75).stdout, '')

    def test_incoming_header_identity_must_match_the_native_addition(self):
        self.prepare(incoming_identity_failure=True)
        self.assertEqual(self.shell(expected=75).stdout, '')

    def test_duplicate_installed_removal_is_refused_before_native_run(self):
        self.prepare(userland_removal=True, duplicate_removal=True)
        self.assertEqual(self.shell(expected=75).stdout, '')
        self.assertNotIn('run 1', self.native_calls())

    def test_aggregate_metadata_bound_refuses_many_valid_individual_arrays(self):
        self.prepare(effects_large_metadata=True)
        result = self.shell(expected=75)
        self.assertIn('effects observations exceed their aggregate bound', result.stderr)
        self.assertNotIn('run 1', self.native_calls())

    def test_declared_tag_type_refusal_is_pending_without_test_run(self):
        self.prepare(effects_wrong_type=True)
        self.shell('s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())
        self.assertNotIn('run 1', self.native_calls())

    def test_prior_audit_success_is_not_a_signature_or_metadata_bypass(self):
        self.prepare()
        self.shell('s4_reconcile_component update-effects yes')
        self.assertIn('status=complete', (self.root / 'state/components/update-effects').read_text())
        self.configure(check_error=True)
        self.shell('s4_reconcile_component update-effects yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())

    def test_backoff_precedes_current_admission_and_native_work(self):
        self.shell('s4_write_state update-effects pending 1 1000030 75; s4_reconcile_component update-effects no', expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_empty_batch_observes_installed_scripts_without_claiming_package_test(self):
        self.prepare(empty=True)
        result = json.loads(self.shell().stdout)
        self.assertFalse(result['rpm_test_performed'])
        self.assertEqual(result['effects']['incoming'], [])
        self.assertEqual(result['effects']['removals'], [])
        self.assertEqual(len(result['effects']['installed_script_owners']), 1)

    def test_missing_audit_delivery_cannot_turn_old_test_proof_into_success(self):
        self.prepare()
        manager = self.root / 'bin/systemd-run'
        manager.write_text(manager.read_text().replace('result = subprocess.run(command, env=environment)',
            "command = [value for value in command if value != 'effects']\nresult = subprocess.run(command, env=environment)"))
        self.assertEqual(self.shell(expected=75).stdout, '')

    def test_capacity_and_effects_modes_cannot_be_combined(self):
        self.prepare()
        self.assertEqual(self.shell('S4_CAPACITY_MODE=yes; s4_check_update_effects', expected=75).stdout, '')
        self.assertEqual(self.native_calls(), [])

    def test_actual_default_dispatch_requires_effects_before_finalization(self):
        self.prepare(effects_wrong_type=True)
        body = f'''
s4_verify_trust_anchor() {{ return 0; }}
s4_verify_bootstrap() {{ return 0; }}
s4_repositories() {{ return 0; }}
s4_verify_repository_trust() {{ return 0; }}
s4_prepare_updates() {{ return 0; }}
s4_check_update_capacity() {{ return 0; }}
s4_check_update_interpreters() {{ return 0; }}
s4_start_timer() {{ return 0; }}
s4_start_repair_timer() {{ touch {shlex.quote(str(self.root / 'retry'))}; }}
s4_finish_repair() {{ touch {shlex.quote(str(self.root / 'finished'))}; }}
s4_repair yes >/dev/null
'''
        self.shell(body, expected=75, timeout=180)
        self.assertFalse((self.root / 'finished').exists())
        self.assertIn('status=pending', (self.root / 'state/components/update-effects').read_text())
        self.configure(); self.shell(body, timeout=180)
        self.assertTrue((self.root / 'finished').exists())
        self.assertIn('status=complete', (self.root / 'state/components/update-effects').read_text())

    def test_generated_policy_includes_another_complete_admission_test_and_controls(self):
        self.assertEqual(int(self.shell('s4_repair_timeout_seconds').stdout), 14540 + 2295 + 4 * 35 + 2600 + 4 * 35)
        # Unit generation is real; activation has separate accepted coverage.
        self.shell('s4_start_repair_timer() { return 0; }; s4_start_timer() { return 0; }; s4_install_units')
        policy = (self.root / 'units/azurelinux3s4-repair.service').read_text()
        self.assertIn('TimeoutStartSec=19715s', policy)
        self.assertIn('TimeoutStopSec=30s', policy)
        self.assertIn('KillMode=control-group', policy)


if __name__ == '__main__':
    unittest.main()

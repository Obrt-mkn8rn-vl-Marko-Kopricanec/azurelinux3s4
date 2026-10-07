import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

import test_package_admission as admission
import test_update_staging as staging


# A disposable ELF implements the vetted public ABI, not real RPM semantics.
# Native Azure RPM execution is a separate gate; these controls deliberately
# model errors which cannot safely be induced against the host RPM database.
LIBRARY = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
const char *RPMVERSION = "4.18.2";
typedef struct { unsigned flags; int n, iteration; char *paths[128]; int upgrade[128]; } TS;
typedef struct { int package; char *path; } H;
typedef void *(*notify_t)(const void *, int, uint64_t, uint64_t, const void *, void *);
static notify_t notify;
static int ran;
static int setting(const char *name) { return getenv(name) && strcmp(getenv(name),"0"); }
static void record(const char *name, int value) {
    char path[8192]; snprintf(path,sizeof(path),"%s/native-calls",getenv("S4_TEST_ROOT"));
    FILE *f=fopen(path,"a"); if (!f) abort(); fprintf(f,"%s %d\n",name,value); fclose(f);
}
__attribute__((constructor)) static void version(void) { if (setting("bad_version")) RPMVERSION="4.19.0"; }
int rpmReadConfigFiles(const char *a,const char *b) { return setting("config_failure"); }
int rpmPushMacro(void *ctx,const char *n,const char *opts,const char *body,int level) {
    if (strcmp(n,"_dbpath") || level!=-7 || !strstr(body,"/database")) abort(); return 0;
}
void *rpmtsCreate(void) { return calloc(1,sizeof(TS)); }
void *rpmtsFree(TS *ts) { for(int i=0;i<ts->n;i++) free(ts->paths[i]); free(ts); return NULL; }
int rpmtsSetRootDir(TS *ts,const char *path) { if(strcmp(path,"/")) abort(); return 0; }
int rpmtsSetDBMode(TS *ts,int mode) { record("db-mode",mode); return mode!=0; }
int rpmtsOpenDB(TS *ts,int mode) { record("db-open",mode); return mode!=0 || setting("db_failure"); }
unsigned rpmtsSetFlags(TS *ts,unsigned flags) { unsigned old=ts->flags; ts->flags=flags; record("flags",flags); return old; }
unsigned rpmtsFlags(TS *ts) { return ts->flags; }
unsigned rpmtsSetVSFlags(TS *ts,unsigned flags) { if(flags) abort(); return 0; }
unsigned rpmtsSetVfyFlags(TS *ts,unsigned flags) { if(flags) abort(); return 0; }
int rpmtsSetVfyLevel(TS *ts,int level) { if(level!=3) abort(); return 0; }
void *rpmKeyringNew(void) { return (void *)1; }
void *rpmPubkeyRead(const char *path) { if(!strstr(path,"/vendor.asc")) abort(); return (void *)2; }
int rpmKeyringAddKey(void *keyring,void *key) { return setting("key_failure"); }
int rpmtsSetKeyring(TS *ts,void *keyring) { return 0; }
void *rpmKeyringFree(void *ptr) { return NULL; }
void *rpmPubkeyFree(void *ptr) { return NULL; }
void *Fopen(const char *path,const char *mode) { if(strcmp(mode,"r.ufdio")) abort(); record("open",1); return fopen(path,"rb"); }
int Ferror(FILE *fd) { return ferror(fd); }
int Fclose(FILE *fd) { record("close",1); return fclose(fd); }
int rpmReadPackageFile(TS *ts,FILE *fd,const char *path,H **out) {
    char data[32]={0}; fread(data,1,31,fd); if(strncmp(data,"signed fixture",14)) return 1;
    if(setting("header_failure")) return 1; *out=calloc(1,sizeof(H)); (*out)->package=1; (*out)->path=strdup(path); return 0;
}
const char *headerGetString(H *h,int tag) { return tag==1000 ? (setting("kernel") ? "kernel" : "userland") : (setting("wrong_arch") ? "aarch64" : "x86_64"); }
int headerIsEntry(H *h,int tag) { if(tag!=1151) abort(); return setting("pretrans"); }
void *headerFree(H *h) { free(h->path); free(h); return NULL; }
int rpmtsAddInstallElement(TS *ts,H *h,const char *path,int upgrade,void *relocs) {
    if(relocs) abort(); record("upgrade",upgrade); if(setting("add_failure")) return 1;
    if(setting("drop_input") && ts->n) return 0;
    ts->paths[ts->n]=strdup(path); ts->upgrade[ts->n++]=upgrade; return 0;
}
int rpmtsCheck(TS *ts) { record("check",1); return setting("check_failure"); }
void *rpmtsProblems(TS *ts) { return (void *)1; }
int rpmpsNumProblems(void *ps) { return setting("dependencies") || ran && setting("run_problem"); }
void *rpmpsFree(void *ps) { return NULL; }
int rpmtsOrder(TS *ts) { record("order",1); return setting("order_failure"); }
int rpmtsNElements(TS *ts) { return ts->n+(setting("kernel_removal") || setting("userland_removal")); }
void *rpmtsElement(TS *ts,int index) { if(setting("missing_element")) return NULL; return (void *)(uintptr_t)(index+1); }
int rpmteType(void *element) { return setting("kernel_removal") || setting("userland_removal") ? ((uintptr_t)element==2 ? 2 : 1) : 1; }
const char *rpmteN(void *element) { return setting("kernel") || setting("kernel_removal") ? "kernel" : "userland"; }
const char *rpmteNEVRA(void *element) { return "userland-1-1.x86_64"; }
static TS *active;
const char *rpmteKey(void *element) { return active->paths[(uintptr_t)element-1]; }
int rpmtsSetNotifyCallback(TS *ts,notify_t cb,void *data) { notify=cb; active=ts; return setting("callback_failure"); }
int rpmtsRun(TS *ts,void *problems,unsigned filters) {
    if(ts->flags!=149 || problems || filters!=384) abort(); record("run",1); ran=1;
    if(setting("run_failure")) return 1;
    for(int i=0;i<ts->n;i++) {
        if(setting("no_callback")) continue;
        const char *path=setting("foreign_callback") ? "/foreign.rpm" : ts->paths[i];
        void *fd=notify(NULL,4,0,0,path,NULL);
        if(fd) { char buf[32]; fread(buf,1,sizeof(buf),fd); }
        if(!setting("no_close")) notify(NULL,8,0,0,path,NULL);
    }
    if(setting("script_callback")) notify(NULL,1<<16,0,0,NULL,NULL);
    return 0;
}
void *rpmtsInitIterator(TS *ts,int tag,void *key,size_t length) { return ts; }
void *rpmdbNextIterator(TS *ts) { return ts->iteration++==0 && !setting("empty_baseline") ? ts : NULL; }
unsigned rpmdbGetIteratorOffset(TS *ts) { return 1; }
void *rpmdbFreeIterator(TS *ts) { return NULL; }
void *headerExport(void *h,unsigned *size) { const char *text=ran && setting("changed_baseline") ? "changed installed header" : "installed header"; *size=strlen(text); return strdup(text); }
int rpmlogSetMask(int mask) { return 0; }
int rpmlogGetNrecsByMask(unsigned mask) { return setting("native_error"); }
'''


class UpdateCompatibilityTests(unittest.TestCase):
    command = admission.PackageAdmissionTests.command
    configure = admission.PackageAdmissionTests.configure
    calls = admission.PackageAdmissionTests.calls

    @classmethod
    def setUpClass(cls):
        cls.temporary_library = tempfile.TemporaryDirectory(prefix='azurelinux3s4-rpm-test-', dir=Path.home() / '.cache')
        cls.addClassCleanup(cls.temporary_library.cleanup)
        cls.library = Path(cls.temporary_library.name) / 'librpm-test.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=LIBRARY, text=True, capture_output=True, check=True)

    def setUp(self):
        staging.UpdateStagingTests.setUp(self)
        (self.root / 'database').mkdir(mode=0o700)
        verifier = self.root / 'bin/rpmkeys'
        verifier.write_text(verifier.read_text().replace(
            "artifact.parent.parent.parent == root / 'state/updates'",
            "(artifact.parent.parent.parent == root / 'state/updates' or artifact.parent.parent.parent == root / 'run')"))
        # Only the manager/namespace delivery and native library are substituted.
        # Store, copying, signatures fixture, hash binding, callback policy and
        # native ABI dispatch remain the actual production functions/program.
        self.command('systemd-run', r'''
import json
import os
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parent.parent
configuration = json.loads((root / 'configuration.json').read_text())
args = sys.argv[1:]
command = args[args.index('--') + 1:]
if '--property=PrivateNetwork=yes' not in args:
    incoming = Path(command[-1].removeprefix('--downloaddir='))
    print('S4_DOWNLOAD_SANDBOX_VERIFIED')
    print('Loaded plugin: tdnfrepogpgcheck')
    if configuration.get('empty'): print('Nothing to do.')
    else:
        (incoming / 'first.rpm').write_bytes((root / 'input.rpm').read_bytes())
        if configuration.get('second'): (incoming / 'second.rpm').write_bytes(b'signed fixture\n')
    sys.exit(0)
required = ['--property=RuntimeMaxSec=12min', '--property=ProtectSystem=strict',
    '--property=CapabilityBoundingSet=', '--property=NoNewPrivileges=yes',
    '--property=PrivateDevices=yes', '--property=MemoryMax=768M',
    '--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket']
assert all(item in args for item in required)
with (root / 'check-sandbox').open('a') as output: output.write(json.dumps(args)+'\n')
environment = dict(os.environ, S4_TEST_ROOT=str(root))
for name,value in configuration.items(): environment[name]=str(int(value)) if isinstance(value,bool) else str(value)
for value in args:
    if value.startswith('--setenv='):
        name,data=value.removeprefix('--setenv=').split('=',1)
        if name != 'PATH': environment[name]=data
program = Path(command[2])
text = program.read_text().replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(os.environ['S4_TEST_LIBRARY']) + ',')
injection = r"""
import types
_read_text, _iterdir = Path.read_text, Path.iterdir
def _fixture_text(path, *args, **options):
    if str(path) == '/proc/self/status':
        return 'CapEff: 0\nCapPrm: 0\nCapBnd: 0\nCapAmb: 0\nNoNewPrivs: '+('0' if os.environ.get('bad_privileges') else '1')+'\n'
    return _read_text(path, *args, **options)
def _fixture_iter(path):
    if str(path) == '/sys/class/net':
        return iter([Path('lo'),Path('eth0')]) if os.environ.get('host_network') else iter([Path('lo')])
    return _iterdir(path)
Path.read_text, Path.iterdir = _fixture_text, _fixture_iter
os.statvfs = lambda path: types.SimpleNamespace(f_flag=0 if os.environ.get('writable_system') else os.ST_RDONLY)
os.access = lambda path, mode: bool(os.environ.get('manager_socket'))
"""
text = text.replace('\ntry:\n', injection + '\ntry:\n', 1)
if configuration.get('change_snapshot'):
    path=program.parent/'packages/0.rpm';path.chmod(0o600);path.write_bytes(b'changed snapshot');path.chmod(0o400)
if configuration.get('unloadable'): text=text.replace(os.environ['S4_TEST_LIBRARY'],str(root/'input.rpm'))
program.write_text(text)
result = subprocess.run(command, env=environment)
sys.exit(result.returncode)
''')

    def header(self):
        return staging.UpdateStagingTests.header(self) + f'''
S4_ARCH=x86_64
export S4_TEST_LIBRARY={shlex.quote(str(self.library))}
s4_rpm_database_path() {{ printf '%s\\n' {shlex.quote(str(self.root / 'database'))}; }}
'''

    def shell(self, body='s4_check_updates', expected=0, timeout=45):
        return staging.UpdateStagingTests.shell(self, body, expected, timeout)

    def prepare(self, **configuration):
        self.configure(**configuration)
        self.shell('s4_prepare_updates >/dev/null')

    def native_calls(self):
        path = self.root / 'native-calls'
        return path.read_text().splitlines() if path.exists() else []

    def test_exact_batch_is_readmitted_and_consumed_in_readonly_native_test(self):
        self.prepare()
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout)
        self.assertTrue(proof['test_passed'])
        self.assertTrue(proof['rpm_test_performed'])
        for name in ('installs_performed', 'scripts_executed', 'installation_authorized', 'storage_capacity_checked', 'freshness_proven'):
            self.assertIs(proof[name], False)
        self.assertEqual(proof['additions'][0]['sha256'], hashlib.sha256(b'signed fixture\n').hexdigest())
        self.assertEqual(proof['additions'][0]['file'], 'packages/0.rpm')
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        calls = self.native_calls()
        self.assertIn('run 1', calls)
        self.assertEqual(calls.count('open 1'), calls.count('close 1'))
        self.assertTrue(all(value == 'db-open 0' for value in calls if value.startswith('db-open')))
        self.assertIn('flags 149', calls)

    def test_kernel_is_added_without_upgrade_or_retention_erase(self):
        self.prepare(kernel=True)
        proof = json.loads(self.shell().stdout)
        self.assertTrue(proof['additions'][0]['install_only'])
        self.assertIn('upgrade 0', self.native_calls())
        self.assertNotIn('upgrade 1', self.native_calls())

    def test_userland_upgrade_and_implicit_removal_are_observed(self):
        self.prepare(userland_removal=True)
        proof = json.loads(self.shell().stdout)
        self.assertIn('upgrade 1', self.native_calls())
        self.assertEqual(len(proof['removals']), 1)

    def test_pretrans_presence_is_reported_without_executing_scripts(self):
        self.prepare(pretrans=True)
        proof = json.loads(self.shell().stdout)
        self.assertTrue(proof['additions'][0]['pretrans_present'])
        self.assertFalse(proof['scripts_executed'])
        self.assertFalse(proof['installation_authorized'])

    def test_kernel_removal_is_refused_before_test_execution(self):
        self.prepare(kernel_removal=True)
        self.shell(expected=75)
        self.assertNotIn('run 1', self.native_calls())

    def test_dependency_problems_are_refused_despite_zero_native_check_exit(self):
        self.prepare(dependencies=True)
        self.shell(expected=75)
        self.assertNotIn('run 1', self.native_calls())

    def test_native_run_and_post_run_problems_do_not_publish(self):
        self.prepare()
        for flag in ('run_failure', 'run_problem', 'native_error'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.shell(expected=75)

    def test_missing_foreign_unclosed_and_script_callbacks_are_refused(self):
        self.prepare()
        for flag in ('no_callback', 'foreign_callback', 'no_close', 'script_callback', 'callback_failure'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.shell(expected=75)

    def test_zero_exit_cannot_drop_a_batch_input(self):
        self.prepare(second=True, drop_input=True)
        self.shell(expected=75)
        self.assertNotIn('run 1', self.native_calls())

    def test_changed_installed_context_cannot_certify(self):
        self.prepare(changed_baseline=True)
        self.shell(expected=75)

    def test_wrong_architecture_header_and_order_failures_defer(self):
        self.prepare()
        for flag in ('wrong_arch', 'header_failure', 'order_failure', 'add_failure', 'check_failure'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.shell(expected=75)

    def test_missing_empty_database_or_native_keyring_defer(self):
        self.prepare()
        for flag in ('db_failure', 'empty_baseline', 'key_failure', 'config_failure'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.shell(expected=75)

    def test_unloadable_or_unvetted_native_abi_defer(self):
        self.prepare()
        for flag in ('unloadable', 'bad_version'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.shell(expected=75)

    def test_in_service_enforcement_is_required_before_native_dispatch(self):
        self.prepare()
        for flag in ('bad_privileges', 'writable_system', 'host_network', 'manager_socket'):
            with self.subTest(flag=flag):
                self.configure(**{flag: True})
                self.shell(expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_snapshot_change_after_readmission_is_refused_before_native_dispatch(self):
        self.prepare(change_snapshot=True)
        self.shell(expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_current_manifest_or_payload_damage_preserves_pointer_and_defers(self):
        self.prepare()
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        path = self.root / 'state/updates/slot0/packages/0.rpm'
        path.chmod(0o600)
        path.write_bytes(b'damaged')
        path.chmod(0o400)
        self.shell(expected=75)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertEqual(self.native_calls(), [])

    def test_repeated_signature_refusal_cannot_reuse_prior_success(self):
        self.prepare()
        self.shell()
        self.configure(check_error=True)
        self.shell(expected=75)

    def test_empty_verified_batch_is_not_labeled_as_a_native_package_test(self):
        self.prepare(empty=True)
        proof = json.loads(self.shell().stdout)
        self.assertFalse(proof['rpm_test_performed'])
        self.assertEqual(proof['additions'], [])
        self.assertEqual(proof['removals'], [])

    def test_compatibility_backoff_precedes_expensive_work(self):
        self.shell('s4_write_state update-compatibility pending 1 1000030 75; s4_reconcile_component update-compatibility no', expected=75)
        self.assertEqual(self.native_calls(), [])
        self.assertFalse((self.root / 'check-sandbox').exists())

    def test_default_component_reconciles_fresh_test_and_preserves_pending_failures(self):
        self.prepare(dependencies=True)
        self.shell('s4_reconcile_component update-compatibility yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-compatibility').read_text())
        self.configure()
        self.shell('s4_reconcile_component update-compatibility yes')
        self.assertIn('status=complete', (self.root / 'state/components/update-compatibility').read_text())
        self.configure(run_failure=True)
        self.shell('s4_reconcile_component update-compatibility yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-compatibility').read_text())

    def test_default_repair_dispatch_defers_until_compatibility_succeeds(self):
        self.prepare(dependencies=True)
        # Exercise the actual default component array and repair dispatch with
        # the real compatibility/store/copy/ABI model. Previously accepted
        # health and timer-finalization behavior has its own retained tests.
        body = f'''
s4_verify_trust_anchor() {{ return 0; }}
s4_verify_bootstrap() {{ return 0; }}
s4_repositories() {{ return 0; }}
s4_verify_repository_trust() {{ return 0; }}
s4_prepare_updates() {{ return 0; }}
# Capacity has separate current-default coverage; keep this accepted case's
# purpose focused on compatibility refusal and its finalization dependency.
s4_check_update_capacity() {{ return 0; }}
s4_check_update_effects() {{ return 0; }}
s4_check_update_interpreters() {{ return 0; }}
s4_check_update_removals() {{ return 0; }}
s4_start_timer() {{ return 0; }}
s4_start_repair_timer() {{ touch {shlex.quote(str(self.root / 'retry'))}; }}
s4_finish_repair() {{ touch {shlex.quote(str(self.root / 'finished'))}; }}
s4_repair yes
'''
        self.shell(body, expected=75)
        self.assertTrue((self.root / 'retry').exists())
        self.assertFalse((self.root / 'finished').exists())
        self.assertIn('status=pending', (self.root / 'state/components/update-compatibility').read_text())
        self.configure()
        self.shell(body)
        self.assertTrue((self.root / 'finished').exists())
        self.assertIn('status=complete', (self.root / 'state/components/update-compatibility').read_text())

    def test_generated_deadline_covers_readmission_store_test_and_state_controls(self):
        deadline = int(self.shell('s4_repair_timeout_seconds').stdout)
        self.assertGreaterEqual(deadline, 9365 + 2 * 35 + 20 + 305 + 65 + 905 + 930 + 4 * 35)
        self.assertLessEqual(deadline, 7 * 60 * 60)

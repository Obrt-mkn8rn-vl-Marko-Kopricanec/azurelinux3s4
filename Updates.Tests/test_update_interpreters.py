import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import test_update_effects as effects
import test_update_compatibility as compatibility
import test_update_staging as staging


SOURCE = Path(__file__).resolve().parents[1] / 'azurelinux3s4.sh'


def emitted(function):
    return subprocess.run(['bash', '-c', 'source "$1"; '+function, 'fixture', str(SOURCE)],
                          capture_output=True, text=True, check=True).stdout


class InterpreterObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = emitted('s4_update_interpreters_program')
        cls.decoder = {'__name__': 'fixture'}
        exec(compile(emitted('s4_rpm_effects_program'), '<effects>', 'exec'), cls.decoder)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-interpreters-', dir=Path.home() / '.cache')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / 'target'
        self.target.mkdir(mode=0o700)
        (self.target / 'usr').mkdir(mode=0o755)
        (self.target / 'usr/bin').mkdir(mode=0o755)
        self.executable = self.target / 'usr/bin/shell'
        self.executable.write_bytes(b'#! /missing-loader\nexit 99\n')
        self.executable.chmod(0o755)
        (self.target / 'bin').symlink_to('usr/bin', target_is_directory=True)
        (self.target / 'usr/bin/sh').symlink_to('shell')
        self.namespace = {'__name__': 'fixture'}
        exec(compile(self.program, '<production-interpreter-observer>', 'exec'), self.namespace)
        # Only root-fd delivery and trusted uid differ in these disposable trees.
        self.namespace['root_open'] = lambda: os.open(self.target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.namespace['TRUSTED_UID'] = os.geteuid()
        self.proof = self.make_proof([(1024, 6, [b'echo never-run'])])

    def make_proof(self, entries):
        owner = {'name': 'fixture', 'nevra': 'fixture-1-1.x86_64', 'instance': 1,
                 **self.decoder['audit_header'](effects.exported(entries))}
        return {'schema': 1, 'manifest_sha256': 'a' * 64, 'baseline': {'headers': 1, 'sha256': 'b' * 64},
                'additions': [], 'removals': [], 'test_passed': True, 'rpm_test_performed': False,
                **{name: False for name in ('installation_authorized', 'scripts_executed', 'installs_performed',
                                            'storage_capacity_checked', 'freshness_proven')},
                'effects': {'schema': 1, 'incoming': [], 'removals': [], 'installed_script_owners': [owner],
                            'installed_headers_observed': 1, 'script_metadata_observed': True,
                            'removals_bound_to_installed_instances': True,
                            **{name: False for name in ('installed_headers_authenticated', 'trigger_selection_complete',
                              'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied',
                              'rollback_policy_satisfied')}}}

    def observe(self, proof=None):
        return self.namespace['observe'](copy.deepcopy(proof or self.proof))['interpreters']

    def test_default_shell_uses_owned_ordinary_symlinks_without_executing_it(self):
        before = self.executable.read_bytes()
        result = self.observe()
        self.assertEqual(result['references'][0]['argv'], ['/bin/sh'])
        self.assertTrue(result['references'][0]['default_program'])
        self.assertEqual(result['files'][0]['resolved_path'], '/usr/bin/shell')
        self.assertEqual(result['files'][0]['sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(self.executable.read_bytes(), before)
        self.assertFalse(result['interpreter_loadability_checked'])
        self.assertFalse(result['interpreter_dependencies_checked'])
        self.assertFalse(result['execution_tested'])

    def test_interpreter_only_legacy_scalar_and_argv_are_preserved(self):
        for kind, argv in ((6, [b'/bin/sh']), (8, [b'/bin/sh', b'-e', b'-c'])):
            with self.subTest(kind=kind):
                result = self.observe(self.make_proof([(1086, kind, argv)]))
                self.assertEqual(result['references'][0]['argv'], [v.decode() for v in argv])
                self.assertFalse(result['references'][0]['default_program'])

    def test_all_ordinary_families_and_each_trigger_entry_are_observed(self):
        entries = [(body, 6, [b'never-run']) for _, body, _ in self.namespace['ORDINARY']]
        for _, body, program in self.namespace['TRIGGERS']:
            entries.extend(((body, 8, [b'a', b'b']), (program, 8, [b'/bin/sh', b'<lua>'])))
        result = self.observe(self.make_proof(entries))
        self.assertEqual(len(result['references']), 13)
        self.assertEqual(result['embedded_lua_declarations'], 3)
        self.assertEqual(len(result['files']), 1)
        self.assertFalse(result['trigger_selection_complete'])

    def test_embedded_lua_is_a_declaration_and_not_engine_availability_proof(self):
        result = self.observe(self.make_proof([(1153, 6, [b'<lua>'])]))
        self.assertEqual(result['embedded_lua_declarations'], 1)
        self.assertEqual(result['files'], [])
        self.assertFalse(result['embedded_engines_tested'])
        self.assertFalse(result['execution_policy_satisfied'])
        self.assertFalse(result['runtime_files_authenticated'])

    def test_relative_empty_control_and_unknown_builtin_interpreters_refuse(self):
        for argv in ([b'sh'], [b'<python>'], [b''], [b'/bin/sh\n'], [b'/bin/sh', b'\t']):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                self.observe(self.make_proof([(1086, 8, argv)]))

    def test_missing_and_dangling_interpreters_refuse_without_repairing_objects(self):
        (self.target / 'usr/bin/sh').unlink()
        with self.assertRaises(FileNotFoundError):
            self.observe()
        (self.target / 'usr/bin/sh').symlink_to('missing')
        with self.assertRaises(FileNotFoundError):
            self.observe()
        self.assertEqual(os.readlink(self.target / 'usr/bin/sh'), 'missing')

    def test_fifo_socket_directory_and_device_leaves_refuse_before_read_open(self):
        leaf = self.target / 'usr/bin/sh'
        leaf.unlink()
        for kind in ('fifo', 'socket', 'directory'):
            with self.subTest(kind=kind):
                server = None
                if kind == 'fifo': os.mkfifo(leaf, 0o600)
                elif kind == 'directory': leaf.mkdir(mode=0o700)
                else:
                    server = socket.socket(socket.AF_UNIX)
                    self.addCleanup(server.close)
                    server.bind(str(leaf))
                original = os.open
                def checked(name, flags, *args, **kwargs):
                    if name == 'sh': self.assertTrue(flags & os.O_PATH)
                    return original(name, flags, *args, **kwargs)
                with patch.object(os, 'open', side_effect=checked), self.assertRaises(ValueError): self.observe()
                self.assertTrue(leaf.exists())
                if server: server.close()
                if kind == 'directory': leaf.rmdir()
                else: leaf.unlink()
        with self.assertRaises(ValueError):
            self.observe(self.make_proof([(1086, 6, [b'/dev/null'])]))

    def test_symlink_to_fifo_refuses_without_opening_or_changing_referent(self):
        self.executable.unlink()
        os.mkfifo(self.executable, 0o700)
        with self.assertRaises(ValueError): self.observe()
        self.assertTrue(stat.S_ISFIFO(self.executable.lstat().st_mode))
        self.assertEqual(os.readlink(self.target / 'usr/bin/sh'), 'shell')

    def test_non_executable_and_writable_leaf_or_ancestor_refuse(self):
        for target, mode in ((self.executable, 0o644), (self.executable, 0o775),
                             (self.target / 'usr/bin', 0o777)):
            with self.subTest(mode=mode, target=target):
                old = target.stat().st_mode
                target.chmod(mode)
                try:
                    with self.assertRaises(ValueError): self.observe()
                finally: target.chmod(stat.S_IMODE(old))

    def test_symlink_and_regular_file_owner_refusals_are_type_aware(self):
        original, original_stat = os.fstat, os.stat
        for symbolic in (True, False):
            def owner(value):
                if (stat.S_ISLNK(value.st_mode) if symbolic else stat.S_ISREG(value.st_mode)):
                    fields = {name: getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                              'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    fields['st_uid'] += 1
                    return types.SimpleNamespace(**fields)
                return value
            # Matching owner substitutions reach the actual type-specific trust
            # branch rather than merely causing a descriptor identity mismatch.
            with (self.subTest(symbolic=symbolic),
                  patch.object(os, 'fstat', side_effect=lambda fd: owner(original(fd))),
                  patch.object(os, 'stat', side_effect=lambda *a, **k: owner(original_stat(*a, **k))),
                  self.assertRaisesRegex(ValueError, 'symlink has' if symbolic else 'ownership/permissions')):
                self.observe()

    def test_noexec_mount_refuses(self):
        with patch.object(os, 'fstatvfs', return_value=types.SimpleNamespace(f_flag=os.ST_NOEXEC)), self.assertRaises(ValueError):
            self.observe()

    def test_every_namespace_leaf_open_is_no_follow_and_identity_is_rechecked(self):
        original, opens = os.open, []
        def checked(name, flags, *args, **kwargs):
            if kwargs.get('dir_fd') is not None:
                opens.append((name, flags))
                self.assertTrue(flags & os.O_NOFOLLOW)
            return original(name, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=checked): self.observe()
        self.assertTrue(opens)
        first, count = self.namespace['resolve'], 0
        def changed(path):
            nonlocal count
            count += 1
            if count == 2:
                self.executable.write_bytes(b'changed executable\n')
            return first(path)
        self.namespace['resolve'] = changed
        with self.assertRaises(ValueError): self.observe()

    def test_relative_parent_and_absolute_links_use_checked_physical_traversal(self):
        (self.target / 'usr/bin/sh').unlink()
        (self.target / 'usr/bin/sh').symlink_to('../bin/shell')
        self.assertEqual(self.observe()['files'][0]['resolved_path'], '/usr/bin/shell')
        (self.target / 'usr/bin/sh').unlink()
        (self.target / 'usr/bin/sh').symlink_to('/usr/bin/shell')
        self.assertEqual(self.observe()['files'][0]['resolved_path'], '/usr/bin/shell')

    def test_link_cycles_and_special_or_noncanonical_paths_refuse(self):
        (self.target / 'usr/bin/sh').unlink()
        (self.target / 'usr/bin/sh').symlink_to('sh')
        with self.assertRaises(ValueError): self.observe()
        for path in ('/proc/self/exe', '/tmp/interpreter', '/bin/../bin/sh', '//bin/sh', '/bin/sh/'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.observe(self.make_proof([(1086, 6, [path.encode()])]))

    def test_leaf_swap_before_no_follow_open_refuses(self):
        original, changed = os.open, False
        def replaced(name, flags, *args, **kwargs):
            nonlocal changed
            if name == 'shell' and not changed:
                changed = True
                self.executable.unlink()
                self.executable.write_bytes(b'replaced executable\n')
                self.executable.chmod(0o755)
            return original(name, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=replaced), self.assertRaisesRegex(ValueError, 'changed before'):
            self.observe()

    def test_descriptor_mount_change_cannot_reuse_an_earlier_observation(self):
        original, number = self.namespace['mount_id'], 0
        def changed(fd):
            nonlocal number
            number += 1
            return original(fd) + (1 if number > 6 else 0)
        self.namespace['mount_id'] = changed
        with self.assertRaisesRegex(ValueError, 'changed during the observation'): self.observe()

    def test_oversized_real_file_refuses_before_content_read(self):
        with self.executable.open('wb') as stream: stream.truncate(64 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, 'bounded executable regular file'): self.observe()

    def test_unique_external_file_bound_refuses_a_large_declared_array(self):
        programs = []
        for index in range(65):
            path = self.target / 'usr/bin' / ('tool' + str(index))
            path.write_bytes(b'never executed\n'); path.chmod(0o755)
            programs.append(('/usr/bin/' + path.name).encode())
        proof = self.make_proof([(1065, 8, [b'body'] * 65), (1092, 8, programs)])
        with self.assertRaisesRegex(ValueError, 'unique interpreter file count'): self.observe(proof)

    def test_trigger_missing_or_mismatched_programs_refuse(self):
        for entries in ([(1065, 8, [b'body'])], [(1092, 8, [b'/bin/sh'])],
                        [(1065, 8, [b'a', b'b']), (1092, 8, [b'/bin/sh'])]):
            with self.subTest(entries=entries), self.assertRaises(ValueError): self.observe(self.make_proof(entries))

    def test_false_missing_or_mismatched_native_and_admission_evidence_refuse(self):
        for modify in (lambda p: p.update(test_passed=False), lambda p: p.update(installation_authorized=True),
                       lambda p: p['effects'].update(removals_bound_to_installed_instances=False),
                       lambda p: p['effects'].update(installed_headers_observed=2),
                       lambda p: p['effects'].update(script_policy_satisfied=True),
                       lambda p: p.update(additions=[{'file': 'packages/0.rpm'}])):
            proof = copy.deepcopy(self.proof); modify(proof)
            with self.subTest(modify=modify), self.assertRaises((ValueError, KeyError)): self.observe(proof)

    def test_duplicate_installed_instances_and_incoming_binding_mismatch_refuse(self):
        proof = copy.deepcopy(self.proof)
        proof['effects']['installed_script_owners'] *= 2
        with self.assertRaises(ValueError): self.observe(proof)
        owner = proof['effects']['installed_script_owners'][0].copy()
        owner.update(file='packages/0.rpm', sha256='c' * 64, bytes=17)
        proof = copy.deepcopy(self.proof)
        proof['effects']['incoming'] = [owner]
        proof['additions'] = [{k: owner[k] for k in ('file', 'sha256', 'bytes', 'nevra')}]
        result = self.observe(proof)
        self.assertEqual({r['source'] for r in result['references']}, {'incoming', 'installed'})
        proof['additions'][0]['sha256'] = 'd' * 64
        with self.assertRaises(ValueError): self.observe(proof)

    def test_private_input_fifo_symlink_and_oversize_refuse_with_zero_json(self):
        workspace = self.root / 'work'; workspace.mkdir()
        program = self.root / 'observer.py'; program.write_text(self.program)
        leaf = workspace / 'result.json'
        for kind in ('fifo', 'symlink', 'oversize'):
            if kind == 'fifo': os.mkfifo(leaf, 0o600)
            elif kind == 'symlink': leaf.symlink_to(self.executable)
            else:
                with leaf.open('wb') as stream: stream.truncate(32 * 1024 * 1024 + 1)
                leaf.chmod(0o600)
            result = subprocess.run(['python3', '-I', str(program), str(workspace)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 75)
            self.assertEqual(result.stdout, '')
            self.assertTrue(leaf.exists())
            leaf.unlink()


# Real public-ABI-shaped exports, but fixture signatures/dependency semantics.
LIBRARY = effects.LIBRARY.replace('void *headerExport(', 'void *fixtureEffectsExport(')
LIBRARY += r'''
void *headerExport(void *h,unsigned *size) {
    const char *body="echo fixture-never-executed";
    const char *program=setting("missing_interpreter") ? "/usr/lib/azurelinux3s4-absent-interpreter" : "/bin/sh";
    if(setting("lua_interpreter")) program="<lua>";
    uint32_t bodytag=incoming(h)?1023:5076, progtag=incoming(h)?1085:5077;
    uint32_t bodykind=incoming(h)?6:8, progkind=8;
    uint32_t bodylen=strlen(body)+1, proglen=strlen(program)+1;
    *size=40+bodylen+proglen;
    unsigned char *result=calloc(1,*size);
    uint32_t fields[]={2,bodylen+proglen,bodytag,bodykind,0,1,progtag,progkind,bodylen,1};
    for(int i=0;i<10;i++) { uint32_t value=htonl(fields[i]); memcpy(result+i*4,&value,4); }
    memcpy(result+40,body,bodylen); memcpy(result+40+bodylen,program,proglen);
    return result;
}
'''


class UpdateInterpreterIntegrationTests(unittest.TestCase):
    command = compatibility.UpdateCompatibilityTests.command
    configure = compatibility.UpdateCompatibilityTests.configure
    calls = compatibility.UpdateCompatibilityTests.calls
    setUp = compatibility.UpdateCompatibilityTests.setUp
    header = compatibility.UpdateCompatibilityTests.header
    prepare = compatibility.UpdateCompatibilityTests.prepare
    native_calls = compatibility.UpdateCompatibilityTests.native_calls

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-interpreter-abi-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup)
        cls.library = Path(temporary.name) / 'librpm-interpreters.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=LIBRARY, text=True, capture_output=True, check=True)

    def shell(self, body='s4_check_update_interpreters', expected=0, timeout=45):
        return staging.UpdateStagingTests.shell(self, body, expected, timeout)

    def test_fresh_admission_test_and_real_host_shell_observation_are_bound_without_execution(self):
        self.prepare(userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = json.loads(self.shell().stdout)
        self.assertEqual(len(result['interpreters']['references']), 2)
        self.assertEqual(result['interpreters']['files'][0]['uid'], 0)
        self.assertEqual(result['interpreters']['files'][0]['sha256'], hashlib.sha256(Path('/bin/sh').read_bytes()).hexdigest())
        self.assertEqual(result['effects']['incoming'][0]['sha256'], result['additions'][0]['sha256'])
        self.assertIn('flags 149', self.native_calls())
        self.assertIn('run 1', self.native_calls())
        self.assertFalse(result['installation_authorized'])
        self.assertFalse(result['scripts_executed'])
        self.assertFalse(result['interpreters']['execution_policy_satisfied'])
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertEqual(list((self.root / 'run').glob('update-check.*')), [])

    def test_missing_file_stays_pending_then_retries_after_fixture_delivery_recovers(self):
        self.prepare(missing_interpreter=True)
        self.shell('s4_reconcile_component update-interpreters yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-interpreters').read_text())
        self.configure()
        self.shell('s4_reconcile_component update-interpreters yes')
        self.assertIn('status=complete', (self.root / 'state/components/update-interpreters').read_text())

    def test_stale_success_does_not_skip_new_file_observation(self):
        self.prepare()
        self.shell('s4_reconcile_component update-interpreters yes')
        self.configure(missing_interpreter=True)
        self.shell('s4_reconcile_component update-interpreters yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-interpreters').read_text())

    def test_backoff_precedes_readmission_and_native_work(self):
        self.shell('s4_write_state update-interpreters pending 1 1000030 75; s4_reconcile_component update-interpreters no', expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_unsupported_mode_and_capacity_combination_refuse_before_work(self):
        for body in ('S4_INTERPRETERS_MODE=yes; s4_check_updates',
                     'S4_CAPACITY_MODE=yes; s4_check_update_interpreters'):
            with self.subTest(body=body): self.shell(body, expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_failed_native_test_never_publishes_interpreter_success(self):
        self.prepare(run_failure=True)
        result = self.shell(expected=75)
        self.assertEqual(result.stdout, '')
        self.assertEqual(list((self.root / 'run').glob('update-check.*')), [])

    def test_builtin_only_native_model_reports_no_external_files_or_engine_test(self):
        self.prepare(lua_interpreter=True)
        result = json.loads(self.shell().stdout)['interpreters']
        self.assertEqual(result['embedded_lua_declarations'], 2)
        self.assertEqual(result['files'], [])
        self.assertFalse(result['embedded_engines_tested'])
        self.assertFalse(result['execution_tested'])

    def test_inherited_internal_mode_is_cleared_at_source(self):
        result = subprocess.run(['bash', '-c', 'S4_INTERPRETERS_MODE=yes; source "$1"; printf "%s" "$S4_INTERPRETERS_MODE"',
                                 'fixture', str(SOURCE)], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, '')

    def test_default_missing_interpreter_keeps_retry_and_blocks_finalization(self):
        self.prepare(missing_interpreter=True)
        self.shell('''
s4_verify_trust_anchor() { return 0; }
s4_verify_bootstrap() { return 0; }
s4_repositories() { return 0; }
s4_verify_repository_trust() { return 0; }
s4_prepare_updates() { return 0; }
s4_check_update_capacity() { return 0; }
s4_start_timer() { return 0; }
s4_start_repair_timer() { touch "$S4_STATE/retry"; }
s4_finish_repair() { touch "$S4_STATE/finished"; }
s4_repair yes >/dev/null
''', expected=75, timeout=180)
        self.assertTrue((self.root / 'state/retry').exists())
        self.assertFalse((self.root / 'state/finished').exists())
        self.assertIn('status=pending', (self.root / 'state/components/update-interpreters').read_text())

    def test_actual_default_dispatch_includes_eighth_component_and_derived_finite_policy(self):
        self.prepare()
        self.shell('''
s4_verify_trust_anchor() { return 0; }
s4_verify_bootstrap() { return 0; }
s4_repositories() { return 0; }
s4_verify_repository_trust() { return 0; }
s4_check_update_capacity() { return 0; }
s4_start_timer() { return 0; }
s4_start_repair_timer() { return 0; }
s4_finish_repair() { return 0; }
s4_repair yes >/dev/null
s4_install_units
''', timeout=180)
        self.assertIn('status=complete', (self.root / 'state/components/update-interpreters').read_text())
        policy = (self.root / 'units/azurelinux3s4-repair.service').read_text()
        self.assertIn('TimeoutStartSec=19715s', policy)
        self.assertIn('TimeoutStopSec=30s', policy)
        self.assertIn('KillMode=control-group', policy)

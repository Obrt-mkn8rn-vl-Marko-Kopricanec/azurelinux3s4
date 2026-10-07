import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_compatibility as compatibility
import test_update_effects as effects
import test_update_interpreters as interpreters
import test_update_staging as staging


SOURCE = Path(__file__).resolve().parents[1] / 'azurelinux3s4.sh'


class RemovalGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = interpreters.emitted('s4_update_removals_program')
        cls.namespace = {'__name__': 'fixture'}
        exec(compile(cls.program, '<production-removal-guard>', 'exec'), cls.namespace)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-removals-', dir=Path.home() / '.cache')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.program_file = self.root / 'removals.py'
        self.program_file.write_text(self.program)
        self.proof = self.make_proof()

    @staticmethod
    def make_proof(name='systemd', arch='x86_64'):
        incoming = {'name': name, 'nevra': name + '-2-1.azl3.' + arch,
                    'file': 'packages/0.rpm', 'sha256': 'c' * 64, 'bytes': 17,
                    'header_bytes': 64, 'header_sha256': 'd' * 64, 'tags': []}
        removed = {'name': name, 'nevra': name + '-1-1.azl3.' + arch,
                   'instance': 7, 'header_bytes': 64, 'header_sha256': 'e' * 64,
                   'classification': 'same-name-replacement', 'tags': []}
        addition = {k: incoming[k] for k in ('file', 'sha256', 'bytes', 'nevra')}
        addition.update(install_only=False, pretrans_present=False)
        return {'schema': 1, 'manifest_sha256': 'a' * 64, 'baseline': {'headers': 2, 'sha256': 'b' * 64},
                'additions': [addition], 'removals': [removed['nevra']], 'test_passed': True, 'rpm_test_performed': True,
                **{name: False for name in ('installation_authorized', 'scripts_executed', 'installs_performed',
                                            'storage_capacity_checked', 'freshness_proven')},
                'effects': {'schema': 1, 'incoming': [incoming], 'removals': [removed], 'installed_script_owners': [],
                            'installed_headers_observed': 2, 'script_metadata_observed': True,
                            'removals_bound_to_installed_instances': True,
                            **{name: False for name in ('installed_headers_authenticated', 'trigger_selection_complete',
                              'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied',
                              'rollback_policy_satisfied')}}}

    def observe(self, proof=None):
        return self.namespace['observe'](copy.deepcopy(self.proof if proof is None else proof))

    def invoke(self, data=None, expected=0):
        path = self.root / 'result.json'
        if data is not None:
            path.write_bytes(data)
            path.chmod(0o600)
        result = subprocess.run(['python3', '-I', str(self.program_file), str(self.root)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, expected, result.stderr)
        if expected:
            self.assertEqual(result.stdout, '')
        return result

    def test_core_and_recovery_package_names_require_exact_replacements(self):
        for name in ('systemd', 'rpm', 'rpm-libs', 'tdnf', 'tdnf-cli-libs', 'tdnf-plugin-repogpgcheck',
                     'glibc', 'bash', 'coreutils', 'util-linux', 'python3', 'gnupg2', 'ca-certificates',
                     'azurelinux-release', 'openssh-server', 'nftables', 'nginx'):
            with self.subTest(name=name):
                result = self.observe(self.make_proof(name))
                match = result['removal_guard']['matches'][0]
                self.assertEqual(match['name'], name)
                self.assertEqual(match['instance'], 7)
                self.assertEqual(match['removed_header_sha256'], 'e' * 64)
                self.assertEqual(match['replacement_header_sha256'], 'd' * 64)
                self.assertFalse(result['removal_guard']['critical_package_closure_complete'])
                self.assertFalse(result['removal_guard']['package_continuity_proven'])

    def test_aarch64_and_noarch_replacement_identities_are_supported_without_execution(self):
        for arch in ('aarch64', 'noarch'):
            with self.subTest(arch=arch):
                self.assertEqual(self.observe(self.make_proof(arch=arch))['removal_guard']['matches'][0]['architecture'], arch)

    def test_epoch_and_rpm_tilde_caret_versions_are_not_compared_or_promoted(self):
        value = self.proof['effects']['incoming'][0]
        value['nevra'] = 'systemd-12:2.0~rc1^git-4.azl3.x86_64'
        self.proof['additions'][0]['nevra'] = value['nevra']
        result = self.observe()['removal_guard']
        self.assertFalse(result['versions_compared_by_guard'])
        self.assertFalse(result['removal_policy_satisfied'])

    def test_obsoleted_or_renamed_package_without_same_name_refuses(self):
        removed = self.proof['effects']['removals'][0]
        removed.update(name='rpm', nevra='rpm-1-1.azl3.x86_64', classification='other-removal')
        self.proof['removals'] = [removed['nevra']]
        with self.assertRaises(ValueError): self.observe()

    def test_native_classification_alone_cannot_approve_a_foreign_replacement(self):
        removed = self.proof['effects']['removals'][0]
        removed.update(name='rpm', nevra='rpm-1-1.azl3.x86_64')
        self.proof['removals'] = [removed['nevra']]
        with self.assertRaises(ValueError): self.observe()

    def test_noarch_or_machine_architecture_transition_refuses(self):
        for arch in ('noarch', 'aarch64'):
            with self.subTest(arch=arch):
                changed = copy.deepcopy(self.proof)
                changed['effects']['incoming'][0]['nevra'] = 'systemd-2-1.azl3.' + arch
                changed['additions'][0]['nevra'] = changed['effects']['incoming'][0]['nevra']
                with self.assertRaises(ValueError): self.observe(changed)

    def test_same_identity_erase_reinstall_is_not_an_update_match(self):
        self.proof['effects']['incoming'][0]['nevra'] = self.proof['removals'][0]
        self.proof['additions'][0]['nevra'] = self.proof['removals'][0]
        with self.assertRaises(ValueError): self.observe()

    def test_kernel_removal_refuses_even_with_same_name_and_architecture(self):
        for name in self.namespace['KERNELS']:
            with self.subTest(name=name):
                proof = self.make_proof(name)
                proof['additions'][0]['install_only'] = True
                with self.assertRaises(ValueError): self.observe(proof)

    def test_new_install_only_kernel_with_no_erasure_preserves_false_authority(self):
        proof = self.make_proof('kernel')
        proof['removals'] = []; proof['effects']['removals'] = []
        proof['additions'][0]['install_only'] = True
        result = self.observe(proof)
        self.assertEqual(result['removal_guard']['matches'], [])
        self.assertFalse(result['installation_authorized'])

    def test_duplicate_incoming_name_architecture_refuses_ambiguous_replacement(self):
        incoming = copy.deepcopy(self.proof['effects']['incoming'][0]); incoming['file'] = 'packages/1.rpm'
        incoming['nevra'] = 'systemd-3-1.azl3.x86_64'
        addition = copy.deepcopy(self.proof['additions'][0]); addition.update(file=incoming['file'], nevra=incoming['nevra'])
        self.proof['effects']['incoming'].append(incoming); self.proof['additions'].append(addition)
        with self.assertRaises(ValueError): self.observe()

    def test_multiple_installed_versions_cannot_share_one_replacement(self):
        removed = copy.deepcopy(self.proof['effects']['removals'][0]); removed.update(instance=8, nevra='systemd-0-1.azl3.x86_64')
        self.proof['effects']['removals'].append(removed); self.proof['removals'].append(removed['nevra'])
        with self.assertRaises(ValueError): self.observe()

    def test_duplicate_actual_database_instance_refuses(self):
        self.proof['effects']['removals'].append(copy.deepcopy(self.proof['effects']['removals'][0]))
        self.proof['removals'].append(self.proof['removals'][0])
        with self.assertRaises(ValueError): self.observe()

    def test_missing_extra_or_changed_native_removal_inventory_refuses(self):
        for replacement in ([], ['foreign-1-1.x86_64'], self.proof['removals'] * 2):
            with self.subTest(replacement=replacement):
                changed = copy.deepcopy(self.proof); changed['removals'] = replacement
                with self.assertRaises(ValueError): self.observe(changed)

    def test_same_byte_binding_requires_file_digest_size_and_identity_correspondence(self):
        for key, value in (('file', 'packages/1.rpm'), ('sha256', 'f' * 64), ('bytes', 18), ('nevra', 'systemd-3-1.azl3.x86_64')):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.proof); changed['additions'][0][key] = value
                with self.assertRaises(ValueError): self.observe(changed)

    def test_missing_false_or_malformed_native_evidence_refuses(self):
        for path, value in ((('schema',), True), (('test_passed',), False), (('rpm_test_performed',), False),
                            (('effects', 'removals_bound_to_installed_instances'), False),
                            (('effects', 'installed_headers_observed'), True), (('effects', 'schema'), True),
                            (('baseline', 'sha256'), 'invalid'), (('baseline', 'headers'), 0), (('effects',), [])):
            with self.subTest(path=path):
                changed = copy.deepcopy(self.proof); target = changed
                for name in path[:-1]: target = target[name]
                target[path[-1]] = value
                with self.assertRaises((ValueError, TypeError)): self.observe(changed)

    def test_unestablished_authority_flags_never_become_removal_success(self):
        for target_name in ('', 'effects'):
            target = self.proof if not target_name else self.proof[target_name]
            for flag in [name for name, value in target.items() if value is False]:
                with self.subTest(target=target_name, flag=flag):
                    changed = copy.deepcopy(self.proof)
                    (changed if not target_name else changed[target_name])[flag] = True
                    with self.assertRaises(ValueError): self.observe(changed)

    def test_untrusted_name_identity_and_instance_types_or_bounds_refuse(self):
        for key, value in (('name', '../rpm'), ('name', 'foreign'), ('nevra', 'systemd-1-1.i686'),
                           ('nevra', 'systemd-1-1.x86_64\n'), ('instance', True), ('instance', 0),
                           ('instance', 2**32), ('header_bytes', 8*1024*1024+1), ('header_sha256', 'invalid')):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.proof); changed['effects']['removals'][0][key] = value
                if key == 'nevra': changed['removals'] = [value]
                with self.assertRaises(ValueError): self.observe(changed)

    def test_empty_batch_reports_no_package_test_and_no_matched_removals(self):
        for key in ('additions', 'removals'): self.proof[key] = []
        for key in ('incoming', 'removals'): self.proof['effects'][key] = []
        self.proof['rpm_test_performed'] = False
        result = self.observe()
        self.assertEqual(result['removal_guard']['matches'], [])
        self.assertFalse(result['rpm_test_performed'])
        self.assertFalse(result['removal_guard']['removal_policy_satisfied'])

    def test_inventory_and_snapshot_numeric_limits_refuse_without_partial_matches(self):
        for key, value in (('file', 'packages/128.rpm'), ('bytes', True), ('bytes', 0),
                           ('bytes', 512*1024*1024+1), ('sha256', 'A'*64)):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(self.proof)
                changed['effects']['incoming'][0][key] = changed['additions'][0][key] = value
                with self.assertRaises(ValueError): self.observe(changed)
        changed = copy.deepcopy(self.proof)
        changed['effects']['incoming'] *= 129; changed['additions'] *= 129
        with self.assertRaises(ValueError): self.observe(changed)
        changed = copy.deepcopy(self.proof)
        changed['effects']['removals'] *= 3; changed['removals'] *= 3
        with self.assertRaises(ValueError): self.observe(changed)

    def test_private_proof_file_hash_and_ordinary_output_are_bound(self):
        data = json.dumps(self.proof).encode()
        result = json.loads(self.invoke(data).stdout)
        self.assertEqual(result['removal_guard']['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual((self.root / 'result.json').read_bytes(), data)

    def test_actual_fifo_socket_directory_and_link_inputs_refuse_without_following(self):
        path = self.root / 'result.json'
        referent = self.root / 'referent'; referent.write_text(json.dumps(self.proof)); referent.chmod(0o600)
        for kind in ('fifo', 'socket', 'directory', 'symlink', 'dangling'):
            with self.subTest(kind=kind):
                server = None
                if kind == 'fifo': os.mkfifo(path, 0o600)
                elif kind == 'socket': server = socket.socket(socket.AF_UNIX); server.bind(str(path))
                elif kind == 'directory': path.mkdir(mode=0o700)
                else: path.symlink_to(referent if kind == 'symlink' else self.root / 'missing')
                before = path.lstat(); self.invoke(expected=75)
                self.assertEqual(path.lstat().st_ino, before.st_ino)
                if server: server.close()
                if kind == 'directory': path.rmdir()
                else: path.unlink()
        self.assertEqual(referent.read_text(), json.dumps(self.proof))

    def test_hardlinked_writable_or_empty_proof_files_refuse(self):
        path = self.root / 'result.json'
        self.invoke(json.dumps(self.proof).encode())
        link = self.root / 'hardlink'; os.link(path, link); self.invoke(expected=75); link.unlink()
        path.chmod(0o640); self.invoke(expected=75)
        self.invoke(b'', expected=75)

    def test_duplicate_json_fields_and_malformed_json_publish_nothing(self):
        for data in (b'{"schema":1,"schema":1}', b'{', b'\xff'):
            with self.subTest(data=data): self.invoke(data, expected=75)

    def test_descriptor_replacement_is_refused_after_nofollow_open(self):
        self.invoke(json.dumps(self.proof).encode())
        old_open = os.open
        def switched(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK)
            path.rename(self.root / 'old-result')
            path.write_text(json.dumps(self.proof)); path.chmod(0o600)
            return old_open(path, flags, *args, **kwargs)
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic), patch.object(os, 'open', side_effect=switched), patch.object(self.namespace['sys'], 'argv',
                                                                 [str(self.program_file), str(self.root)]), \
                patch.object(self.namespace['resource'], 'setrlimit'):
            self.assertEqual(self.namespace['main'](), 75)
        self.assertIn('changed before opening', diagnostic.getvalue())


class UpdateRemovalIntegrationTests(unittest.TestCase):
    command = compatibility.UpdateCompatibilityTests.command
    configure = compatibility.UpdateCompatibilityTests.configure
    calls = compatibility.UpdateCompatibilityTests.calls
    setUp = compatibility.UpdateCompatibilityTests.setUp
    header = compatibility.UpdateCompatibilityTests.header
    prepare = compatibility.UpdateCompatibilityTests.prepare
    native_calls = compatibility.UpdateCompatibilityTests.native_calls

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-removal-abi-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup)
        cls.library = Path(temporary.name) / 'librpm-removals.so'
        # Public ABI/error delivery model, NOT genuine RPM semantics/signatures.
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=effects.LIBRARY, text=True, capture_output=True, check=True)

    def shell(self, body='s4_check_update_removals', expected=0, timeout=45):
        return staging.UpdateStagingTests.shell(self, body, expected, timeout)

    def test_fresh_same_byte_admission_test_and_bound_removal_match_preserve_pointer(self):
        self.prepare(userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout)
        match = proof['removal_guard']['matches'][0]
        self.assertEqual(match['instance'], 1)
        self.assertEqual(match['sha256'], proof['additions'][0]['sha256'])
        self.assertEqual(match['removed_nevra'], proof['removals'][0])
        self.assertIn('flags 149', self.native_calls()); self.assertIn('run 1', self.native_calls())
        self.assertFalse(proof['installation_authorized']); self.assertFalse(proof['scripts_executed'])
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertEqual(list((self.root / 'run').glob('update-check.*')), [])

    def test_other_removal_defers_then_new_fresh_fixture_batch_can_recover(self):
        self.prepare(userland_removal=True, installed_other=True)
        result = self.shell('s4_reconcile_component update-removals yes', expected=75)
        self.assertEqual(result.stdout, '')
        self.assertIn('status=pending', (self.root / 'state/components/update-removals').read_text())
        self.configure(userland_removal=True)
        self.shell('s4_reconcile_component update-removals yes')
        self.assertIn('status=complete', (self.root / 'state/components/update-removals').read_text())

    def test_stale_success_does_not_skip_current_admission_test_and_removal_check(self):
        self.prepare(userland_removal=True)
        self.shell('s4_reconcile_component update-removals yes')
        self.configure(userland_removal=True, installed_other=True)
        self.shell('s4_reconcile_component update-removals yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-removals').read_text())

    def test_backoff_precedes_current_package_or_native_work(self):
        self.shell('s4_write_state update-removals pending 1 1000030 75; s4_reconcile_component update-removals no', expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_conflicting_internal_modes_refuse_before_native_work(self):
        for body in ('S4_REMOVALS_MODE=yes; s4_check_updates', 'S4_CAPACITY_MODE=yes; s4_check_update_removals',
                     'S4_INTERPRETERS_MODE=yes; s4_check_update_removals', 'S4_REMOVALS_MODE=foreign; s4_check_update_effects'):
            with self.subTest(body=body): self.shell(body, expected=75)
        self.assertEqual(self.native_calls(), [])

    def test_failed_verification_native_test_and_installed_context_publish_nothing(self):
        self.prepare(userland_removal=True)
        for flag in ('check_error', 'run_failure', 'changed_baseline', 'script_callback'):
            with self.subTest(flag=flag):
                self.configure(userland_removal=True, **{flag: True})
                self.assertEqual(self.shell(expected=75).stdout, '')

    def test_corrupt_retained_bytes_cannot_reuse_a_prior_match(self):
        self.prepare(userland_removal=True)
        self.shell()
        pointer = json.loads((self.root / 'state/updates/current.json').read_text())
        package = self.root / 'state/updates' / ('slot' + pointer['slot']) / 'packages/0.rpm'
        package.chmod(0o600); package.write_bytes(b'damaged signed fixture\n')
        self.assertEqual(self.shell(expected=75).stdout, '')

    def test_missing_effects_delivery_cannot_certify_guard(self):
        self.prepare()
        manager = self.root / 'bin/systemd-run'
        data = manager.read_text()
        marker = 'result = subprocess.run(command, env=environment)'
        self.assertIn(marker, data)
        manager.write_text(data.replace(marker, 'import types\nresult = types.SimpleNamespace(returncode=0)'))
        self.assertEqual(self.shell(expected=75).stdout, '')

    def test_empty_batch_has_zero_matches_and_keeps_false_package_test(self):
        self.prepare(empty=True)
        proof = json.loads(self.shell().stdout)
        self.assertEqual(proof['removal_guard']['matches'], [])
        self.assertFalse(proof['rpm_test_performed'])
        self.assertFalse(proof['removal_guard']['removal_policy_satisfied'])

    def test_inherited_removal_mode_is_cleared_on_source(self):
        result = subprocess.run(['bash', '-c', 'S4_REMOVALS_MODE=yes; source "$1"; printf "%s" "$S4_REMOVALS_MODE"',
                                'fixture', str(SOURCE)], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, '')

    def default_body(self):
        # Real nine-component dispatch and current compatibility/effects/removal
        # routes. Trust/bootstrap/network/capacity/interpreter/manager delivery
        # is substituted; no host package/service is changed. Interpreter file
        # observations have separate accepted controls in their own component.
        return '''
s4_verify_trust_anchor() { return 0; }
s4_verify_bootstrap() { return 0; }
s4_repositories() { return 0; }
s4_verify_repository_trust() { return 0; }
s4_prepare_updates() { return 0; }
s4_check_update_capacity() { return 0; }
s4_check_update_interpreters() { return 0; }
s4_start_timer() { return 0; }
s4_start_repair_timer() { touch "$S4_STATE/retry"; }
s4_finish_repair() { touch "$S4_STATE/finished"; }
s4_repair yes >/dev/null
'''

    def test_ninth_default_dependency_blocks_finalization_and_preserves_retry(self):
        self.prepare(userland_removal=True, installed_other=True)
        self.shell(self.default_body(), expected=75, timeout=180)
        self.assertTrue((self.root / 'state/retry').exists())
        self.assertFalse((self.root / 'state/finished').exists())
        self.assertIn('status=pending', (self.root / 'state/components/update-removals').read_text())

    def test_ninth_default_dependency_can_complete_after_fresh_matches(self):
        self.prepare(userland_removal=True)
        self.shell(self.default_body(), timeout=180)
        self.assertTrue((self.root / 'state/finished').exists())
        self.assertIn('status=complete', (self.root / 'state/components/update-removals').read_text())

    def test_cli_component_and_verifier_route_removals_without_claiming_readiness(self):
        self.prepare(userland_removal=True)
        preflight = '''s4_preflight() { return 0; }; s4_prepare_state() { return 0; }; s4_lock() { return 0; };
s4_verify_trust_anchor() { return 0; }; s4_main'''
        # s4_main resets PATH; restore only the disposable tool delivery inside
        # the overridden preflight, before any actual diagnostic runs.
        preflight = preflight.replace('s4_preflight() { return 0; }',
                                      's4_preflight() { export PATH="$S4_FIXTURE_PATH"; }')
        prefix = 'export S4_FIXTURE_PATH="$PATH"; '
        for action in ('--check-update-removals', '--component update-removals'):
            with self.subTest(action=action):
                proof = json.loads(self.shell(prefix + preflight + ' ' + action).stdout)
                self.assertTrue(proof['removal_guard']['same_name_architecture_replacements_only'])
        self.assertTrue(json.loads(self.shell('s4_verify_component update-removals').stdout)['test_passed'])
        self.assertIn('server_ready=no', self.shell('s4_status').stdout)

    def test_generated_finite_budget_covers_fresh_test_observer_and_persistence(self):
        self.assertEqual(int(self.shell('s4_repair_timeout_seconds').stdout), 19715 + 2295 + 95 + 4 * 35)
        self.shell('s4_start_repair_timer() { return 0; }; s4_start_timer() { return 0; }; s4_install_units')
        policy = (self.root / 'units/azurelinux3s4-repair.service').read_text()
        self.assertIn('TimeoutStartSec=22245s', policy)
        self.assertIn('TimeoutStopSec=30s', policy); self.assertIn('KillMode=control-group', policy)


if __name__ == '__main__':
    unittest.main()

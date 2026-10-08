import copy
from contextlib import redirect_stderr, redirect_stdout
import ctypes as C
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_compatibility as compatibility
import test_update_interpreters as interpreters
import test_update_removals as removals


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'Updates.Tests/rpm_version_model.c'


class ReplacementVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-version-abi-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup)
        cls.library = Path(temporary.name) / 'librpm-version-model.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', str(MODEL), '-o', str(cls.library)],
                       input=compatibility.LIBRARY, text=True, capture_output=True, check=True)
        cls.missing_library = Path(temporary.name) / 'librpm-missing-comparison-model.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.missing_library)],
                       input=compatibility.LIBRARY, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library)); cls.lib.rpmvercmp.argtypes = (C.c_char_p, C.c_char_p)
        cls.lib.rpmvercmp.restype = C.c_int
        cls.program = interpreters.emitted('s4_update_removals_program')
        cls.namespace = {'__name__': 'fixture'}
        exec(compile(cls.program, '<actual-version-client>', 'exec'), cls.namespace)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='s4-version-proof-')
        self.addCleanup(temporary.cleanup); self.root = Path(temporary.name)
        self.proof = removals.RemovalGuardTests.make_proof()
        self.script = self.root / 'guard.py'
        self.assertEqual(self.program.count('C.CDLL("librpm.so.9",'), 1)
        self.script.write_text(self.program.replace('C.CDLL("librpm.so.9",',
                                                   'C.CDLL(' + repr(str(self.library)) + ','))

    def compare(self, left, right):
        return self.lib.rpmvercmp(left.encode('ascii'), right.encode('ascii'))

    def pair(self, old, new):
        incoming = self.proof['effects']['incoming'][0]
        removed = self.proof['effects']['removals'][0]
        incoming['nevra'] = 'systemd-' + new + '.x86_64'
        removed['nevra'] = 'systemd-' + old + '.x86_64'
        self.proof['additions'][0]['nevra'] = incoming['nevra']
        self.proof['removals'] = [removed['nevra']]

    def observe(self, factory=None):
        value = self.namespace['observe'](copy.deepcopy(self.proof))
        return self.namespace['version_observe'](value, factory or (lambda: self.compare))

    def invoke(self, data=None, expected=0, environment=None):
        path = self.root / 'result.json'
        if data is not None: path.write_bytes(data); path.chmod(0o600)
        result = subprocess.run(['python3', '-I', str(self.script), str(self.root)],
                                capture_output=True, timeout=5, env=environment)
        self.assertEqual(result.returncode, expected, result.stderr.decode())
        if expected: self.assertEqual(result.stdout, b'')
        return result

    def test_positive_pair_keeps_exact_instance_header_snapshot_binding_and_false_policy(self):
        proof = self.observe(); match = proof['replacement_version_guard']['matches'][0]
        self.assertEqual(match['instance'], 7)
        self.assertEqual(match['removed_header_sha256'], 'e' * 64)
        self.assertEqual(match['replacement_header_sha256'], 'd' * 64)
        self.assertEqual(match['sha256'], 'c' * 64)
        self.assertEqual(match['file'], 'packages/0.rpm')
        self.assertEqual(proof['replacement_version_guard']['pairs_compared'], 1)
        self.assertTrue(proof['replacement_version_guard']['observed_replacement_pairs_strictly_newer'])
        self.assertFalse(proof['removal_guard']['versions_compared_by_guard'])
        for flag in ('anti_rollback_proven', 'freshness_proven', 'all_incoming_versions_checked',
                     'kernel_version_policy_satisfied', 'installation_authorized', 'server_ready'):
            self.assertIs(proof['replacement_version_guard'][flag], False)

    def test_numeric_segment_order_is_not_lexical_order(self):
        self.pair('1.9-1.azl3', '1.10-1.azl3')
        match = self.observe()['replacement_version_guard']['matches'][0]
        self.assertEqual(match['comparisons'][-1]['component'], 'version')
        self.assertEqual(match['comparisons'][-1]['result'], 1)

    def test_epoch_dominates_a_lower_version(self):
        self.pair('1:2.0-1.azl3', '2:1.0-1.azl3')
        decision = self.observe()['replacement_version_guard']['matches'][0]['comparisons']
        self.assertEqual(decision, [{'component': 'epoch', 'incoming': '2', 'installed': '1', 'result': 1}])

    def test_release_is_compared_after_equal_epoch_and_version(self):
        self.pair('1.0-1.azl3', '1.0-2.azl3')
        decisions = self.observe()['replacement_version_guard']['matches'][0]['comparisons']
        self.assertEqual([row['component'] for row in decisions], ['epoch', 'version', 'release'])
        self.assertEqual([row['result'] for row in decisions], [0, 0, 1])

    def test_tilde_and_caret_cases_require_native_order(self):
        for old, new in (('1.0~rc1', '1.0'), ('1.0', '1.0^git'), ('1.0^git', '1.0.1')):
            with self.subTest(old=old, new=new):
                self.pair(old + '-1.azl3', new + '-1.azl3')
                self.assertEqual(self.observe()['replacement_version_guard']['pairs_compared'], 1)

    def test_epoch_version_and_release_downgrades_refuse(self):
        for old, new in (('2:1-1.azl3', '1:2-1.azl3'), ('2-1.azl3', '1-1.azl3'),
                         ('1-2.azl3', '1-1.azl3'), ('1.0-1.azl3', '1.0~rc1-1.azl3')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                self.pair(old, new); self.observe()

    def test_absent_zero_epoch_and_semantically_equal_versions_refuse(self):
        for old, new in (('1-1.azl3', '0:1-1.azl3'), ('1.01-1.azl3', '1.1-1.azl3'),
                         ('1.0-1.azl3', '1.00-1.azl3')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                self.pair(old, new); self.observe()

    def test_supported_canonical_epoch_and_name_with_hyphens_are_bound(self):
        evr = self.namespace['version_evr']
        self.assertEqual(evr('dotnet-runtime-10.0', 'dotnet-runtime-10.0-4294967295:10.0.2-4.azl3.aarch64', 'aarch64'),
                         ('4294967295', '10.0.2', '4.azl3'))
        self.assertEqual(evr('rpm-libs', 'rpm-libs-4.18.2-1.azl3.noarch', 'noarch'), ('0', '4.18.2', '1.azl3'))

    def test_unsupported_epoch_identity_encoding_or_architecture_refuses(self):
        for identity, arch in (('systemd-01:1-1.x86_64', 'x86_64'), ('systemd-4294967296:1-1.x86_64', 'x86_64'),
                               ('systemd-1-1.i686', 'i686'), ('foreign-1-1.x86_64', 'x86_64'),
                               ('systemd-1\u2028-1.x86_64', 'x86_64'), ('systemd-1-1.x86_64\n', 'x86_64')):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                self.namespace['version_evr']('systemd', identity, arch)

    def test_native_controls_check_forward_reverse_and_both_self_comparisons(self):
        rows = self.observe()['replacement_version_guard']['ordering_controls']
        self.assertEqual(len(rows), 9)
        for row, (_, _, expected) in zip(rows, self.namespace['VERSION_PROBES']):
            self.assertEqual(row['observed'], [expected, -expected, 0, 0])

    def test_always_positive_zero_invalid_and_boolean_delivery_cannot_pass_controls(self):
        for result in (1, 0, 42, True):
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.observe(lambda: lambda left, right: result)

    def test_missing_native_library_refuses_before_success(self):
        with patch.object(self.namespace['C'], 'CDLL', side_effect=OSError('missing native library')):
            with self.assertRaises(OSError): self.namespace['version_native']()

    def test_unsupported_native_machine_refuses_before_loader(self):
        with patch.object(self.namespace['platform'], 'machine', return_value='i686'), \
                patch.object(self.namespace['C'], 'CDLL', side_effect=AssertionError('loader called')):
            with self.assertRaises(ValueError): self.namespace['version_native']()

    def test_actual_missing_model_symbol_is_a_bounded_refusal(self):
        lib = C.CDLL(str(self.missing_library))
        with patch.object(self.namespace['C'], 'CDLL', return_value=lib):
            with self.assertRaisesRegex(ValueError, 'comparison function is missing'):
                self.namespace['version_native']()

    def test_native_loader_binds_actual_model_symbol_and_vetted_abi_receipt(self):
        with patch.object(self.namespace['C'], 'CDLL', return_value=self.lib):
            compare = self.namespace['version_native']()
            self.assertEqual(compare('1.10', '1.9'), 1)
            self.assertEqual(compare('1.01', '1.1'), 0)
            self.assertEqual(compare('1.0~rc1', '1.0'), -1)

    def test_partial_batch_refusal_does_not_publish_prefix_matches(self):
        second = removals.RemovalGuardTests.make_proof('rpm')
        incoming = second['effects']['incoming'][0]; incoming['file'] = 'packages/1.rpm'
        second['additions'][0]['file'] = 'packages/1.rpm'
        removed = second['effects']['removals'][0]; removed['instance'] = 8
        incoming['nevra'] = 'rpm-0-1.azl3.x86_64'; second['additions'][0]['nevra'] = incoming['nevra']
        for key in ('additions', 'removals'): self.proof[key] += second[key]
        for key in ('incoming', 'removals'): self.proof['effects'][key] += second['effects'][key]
        result = self.invoke(json.dumps(self.proof).encode(), expected=75)
        self.assertIn(b'downgrade or version-equivalent', result.stderr)

    def test_zero_pairs_does_not_claim_package_version_test_or_kernel_policy(self):
        self.proof['additions'] = self.proof['removals'] = []
        self.proof['effects']['incoming'] = self.proof['effects']['removals'] = []
        self.proof['rpm_test_performed'] = False
        result = self.observe()['replacement_version_guard']
        self.assertEqual(result['matches'], []); self.assertEqual(result['pairs_compared'], 0)
        self.assertFalse(result['observed_replacement_pairs_strictly_newer'])
        self.assertFalse(result['all_incoming_versions_checked'])
        self.assertFalse(result['kernel_version_policy_satisfied'])

    def test_current_correspondence_missing_claimed_or_excessive_guard_refuses(self):
        proof = self.namespace['observe'](copy.deepcopy(self.proof))
        for change in ({'schema': True}, {'installation_authorized': True}, {'matches': [None] * 129},
                       {'same_name_architecture_replacements_only': False}):
            value = copy.deepcopy(proof); value['removal_guard'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.namespace['version_observe'](value, lambda: self.compare)

    def test_private_cli_binds_both_guard_digests_and_preserves_input(self):
        data = json.dumps(self.proof).encode(); result = json.loads(self.invoke(data).stdout)
        for name in ('removal_guard', 'replacement_version_guard'):
            self.assertEqual(result[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual((self.root / 'result.json').read_bytes(), data)
        self.assertEqual(result['replacement_version_guard']['pairs_compared'], 1)

    def test_private_cli_native_invalid_result_and_wrong_version_publish_no_json(self):
        data = json.dumps(self.proof).encode()
        for environment in ({'S4_VERSION_MODEL_FAULT': 'invalid'}, {'bad_version': '1'}):
            with self.subTest(environment=environment):
                result = self.invoke(data, expected=75, environment={**os.environ, **environment})
                self.assertIn(b'Update replacement version safeguard deferred:', result.stderr)

    def test_private_cli_duplicate_json_and_ordinary_wrong_kind_objects_refuse(self):
        self.invoke(b'{"schema":1,"schema":1}', expected=75)
        path = self.root / 'result.json'; path.unlink(); os.mkfifo(path, 0o600)
        inode = path.lstat().st_ino; self.invoke(expected=75); self.assertEqual(path.lstat().st_ino, inode)
        path.unlink(); path.symlink_to(self.root / 'absent')
        inode = path.lstat().st_ino; self.invoke(expected=75); self.assertEqual(path.lstat().st_ino, inode)

    def test_private_cli_inode_swap_withholds_all_output(self):
        data = json.dumps(self.proof).encode(); self.invoke(data)
        opened = os.open
        def replaced(path, flags):
            self.assertTrue(flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK and flags & os.O_CLOEXEC)
            path.rename(self.root / 'old-result'); path.write_bytes(data); path.chmod(0o600)
            return opened(path, flags)
        output,error=io.StringIO(),io.StringIO()
        with patch.object(self.namespace['sys'], 'argv', [str(self.script), str(self.root)]), \
                patch.object(self.namespace['resource'], 'setrlimit'), patch.object(os, 'open', side_effect=replaced), \
                redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(self.namespace['version_main'](self.namespace['observe']), 75)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('changed before reading', error.getvalue())

    def test_ordinary_private_snapshot_close_failure_precedes_native_and_output(self):
        data = json.dumps(self.proof).encode(); self.invoke(data)
        original = os.fdopen
        def delivery(descriptor, *args, **kwargs):
            stream = original(descriptor, *args, **kwargs)
            class FailedClose:
                def __enter__(self): return stream
                def __exit__(self, *ignored):
                    stream.close()
                    raise OSError('delivered ordinary close failure')
            return FailedClose()
        output,error=io.StringIO(),io.StringIO()
        with patch.object(self.namespace['sys'], 'argv', [str(self.script), str(self.root)]), \
                patch.object(self.namespace['resource'], 'setrlimit'), patch.object(os, 'fdopen', side_effect=delivery), \
                patch.dict(self.namespace, version_observe=lambda *args: self.fail('native work after failed close')), \
                redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(self.namespace['version_main'](self.namespace['observe']), 75)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('ordinary close failure', error.getvalue())


class ReplacementVersionIntegrationTests(unittest.TestCase):
    setUpClass = classmethod(removals.UpdateRemovalIntegrationTests.setUpClass.__func__)
    setUp = removals.UpdateRemovalIntegrationTests.setUp
    command = removals.UpdateRemovalIntegrationTests.command
    configure = removals.UpdateRemovalIntegrationTests.configure
    calls = removals.UpdateRemovalIntegrationTests.calls
    header = removals.UpdateRemovalIntegrationTests.header
    prepare = removals.UpdateRemovalIntegrationTests.prepare
    native_calls = removals.UpdateRemovalIntegrationTests.native_calls
    shell = removals.UpdateRemovalIntegrationTests.shell

    def test_fresh_same_byte_pipeline_requires_positive_version_pairs_and_cleanup(self):
        self.prepare(userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        proof = json.loads(self.shell().stdout)
        self.assertEqual(proof['replacement_version_guard']['pairs_compared'], 1)
        self.assertTrue(proof['replacement_version_guard']['observed_replacement_pairs_strictly_newer'])
        self.assertEqual(proof['replacement_version_guard']['matches'][0]['sha256'], proof['additions'][0]['sha256'])
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertEqual(list((self.root / 'run').glob('update-check.*')), [])
        self.assertFalse(proof['installation_authorized'])

    def test_bad_ordering_keeps_pending_then_fresh_pipeline_can_retry(self):
        self.prepare(userland_removal=True)
        result = self.shell('export S4_VERSION_MODEL_FAULT=positive; s4_reconcile_component update-removals yes', expected=75)
        self.assertEqual(result.stdout, '')
        self.assertIn('status=pending', (self.root / 'state/components/update-removals').read_text())
        before = len(self.native_calls())
        self.shell('s4_reconcile_component update-removals yes')
        self.assertGreater(len(self.native_calls()), before)
        self.assertIn('status=complete', (self.root / 'state/components/update-removals').read_text())

    def test_current_bad_ordering_cannot_reuse_prior_success_receipt(self):
        self.prepare(userland_removal=True)
        self.shell('s4_reconcile_component update-removals yes')
        self.shell('export S4_VERSION_MODEL_FAULT=zero; s4_reconcile_component update-removals yes', expected=75)
        self.assertIn('status=pending', (self.root / 'state/components/update-removals').read_text())


if __name__ == '__main__': unittest.main()

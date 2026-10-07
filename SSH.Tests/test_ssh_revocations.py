import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('s4_revocation_keys', ROOT / 'SSH/keys.py')
KEYS = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(KEYS)
sys.path.insert(0, str(ROOT / 'SSH.Tests'))
from test_ssh_keys import ed, rsa


class SSHRevocationFormatTests(unittest.TestCase):
    def test_empty_revocation_is_explicit_but_not_a_valid_empty_candidate(self):
        self.assertEqual(KEYS.parse(b'', allow_empty=True), [])
        self.assertEqual(KEYS.parse(b'# explicit list\n\n', allow_empty=True), [])
        for data in (b'', b'# no candidate\n'):
            with self.assertRaises(ValueError): KEYS.parse(data)

    def test_revoked_public_records_keep_strict_full_wire_and_strong_input_policy(self):
        values = KEYS.parse(ed(1) + rsa(), allow_empty=True)
        self.assertEqual([key['type'] for key in values], ['ssh-ed25519', 'ssh-rsa'])
        for data in (b'SSHKRL\n\0binary', b'SHA256:borrowed\n', b'restrict ' + ed(), rsa(2048), ed()[:-1], ed() + ed()):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError): KEYS.parse(data, allow_empty=True)

    def test_zero_file_is_permitted_only_for_explicit_revocation_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='s4-empty-revocation-') as directory:
            path = Path(directory) / 'revoked'; path.write_bytes(b''); path.chmod(0o600)
            self.assertEqual(KEYS.snapshot(path, allow_empty=True), b'')
            with self.assertRaises(ValueError): KEYS.snapshot(path)

    def test_empty_wrong_kind_or_writable_revocation_inputs_still_refuse(self):
        with tempfile.TemporaryDirectory(prefix='s4-empty-revocation-kind-') as directory:
            base = Path(directory); empty = base / 'empty'; empty.write_bytes(b''); empty.chmod(0o666)
            link = base / 'linked'; link.symlink_to(empty)
            fifo = base / 'fifo'; os.mkfifo(fifo, 0o600)
            for path in (empty, link, fifo, base):
                before = KEYS.identity(path.lstat())
                with mock.patch.object(KEYS.os, 'open', side_effect=AssertionError('must refuse before open')):
                    with self.assertRaises(ValueError): KEYS.snapshot(path, allow_empty=True)
                self.assertEqual(KEYS.identity(path.lstat()), before)

    def test_non_boolean_empty_permission_cannot_relax_snapshot_or_parser(self):
        for value in ('yes', 1, [], None):
            with self.assertRaises(ValueError): KEYS.parse(b'', allow_empty=value)


class SSHRevocationNativeDeliveryTests(unittest.TestCase):
    def run_model(self, revoked_data=b'', fault=None, overlap=False):
        keys = KEYS.parse(ed(1)); revoked = KEYS.parse(ed(1) if overlap else revoked_data, allow_empty=True)
        folders, commands = [], []
        supplied_fingerprints = {key['fingerprint'] for key in revoked}
        def run(command, **kwargs):
            commands.append(command)
            self.assertEqual(command[0], '/usr/bin/ssh-keygen')
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(kwargs['timeout'], 10)
            if command[1] == '-k':
                dest = Path(command[4]); source = Path(command[5]); folders.append(dest.parent)
                self.assertEqual(stat.S_IMODE(dest.parent.stat().st_mode), 0o700)
                content = b'SSHKRL\n\0delivery-model-only'
                if fault == 'bad-header': content = b'not a KRL'
                dest.write_bytes(content); dest.chmod(0o600)
                if fault == 'build-exit': return subprocess.CompletedProcess(command, 42)
                if fault == 'build-output': kwargs['stdout'].write(b'unsupported record\n')
                self.assertTrue(source.is_file())
                return subprocess.CompletedProcess(command, 0)
            self.assertEqual(command[1:3], ['-Q', '-f'])
            krl = Path(command[3]); lines, states = [], []
            for name in command[4:]:
                path = Path(name)
                public = KEYS.parse(path.read_bytes())[0]
                state = krl.name == 'positive.krl' or (krl.name == 'supplied.krl' and public['fingerprint'] in supplied_fingerprints)
                states.append(state)
                lines.append(str(path) + ' (' + KEYS.COMMENT + '): ' + ('REVOKED' if state else 'ok') + '\n')
            output = ''.join(lines).encode(); result = int(any(states))
            if fault == 'positive-disabled' and krl.name == 'positive.krl': output = output.replace(b'REVOKED', b'ok'); result = 0
            if fault == 'negative-revoked' and krl.name == 'empty.krl': output = output.replace(b'ok', b'REVOKED'); result = 1
            if fault == 'query-missing': output = b''
            if fault == 'query-extra': output += b'unrelated\n'
            if fault == 'query-reversed': output = b''.join(reversed(output.splitlines(keepends=True)))
            if fault == 'query-warning': kwargs['stderr'].write(b'warning\n')
            if fault == 'query-error': result = 42
            if fault == 'oversized-output': output = b'x' * 32769
            if fault == 'mutated-query-input': Path(command[4]).write_bytes(ed(3))
            if fault == 'skipped-supplied-revocation' and krl.name == 'supplied.krl': output = output.replace(b'REVOKED', b'ok'); result = 0
            kwargs['stdout'].write(output)
            return subprocess.CompletedProcess(command, result)
        with mock.patch.object(KEYS.subprocess, 'run', side_effect=run):
            if fault or overlap:
                with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                    KEYS.native_revocations(keys, revoked)
                receipt = None
            else:
                receipt = KEYS.native_revocations(keys, revoked)
        self.assertTrue(folders)
        self.assertTrue(all(not folder.exists() for folder in folders))
        return receipt, commands

    def test_native_empty_and_listed_comparison_requires_all_three_control_receipts(self):
        for data in (b'', ed(2)):
            receipt, commands = self.run_model(data)
            self.assertEqual([item['control'] for item in receipt], ['known-negative', 'known-positive', 'supplied'])
            self.assertEqual([item['actual_native_exit'] for item in receipt], [0, 1, int(bool(data))])
            self.assertEqual(len(commands), 6)

    def test_known_positive_must_actually_report_revocation(self):
        self.run_model(fault='positive-disabled')

    def test_known_negative_must_not_borrow_revoked_state(self):
        self.run_model(fault='negative-revoked')

    def test_krl_builder_exit_output_and_bad_header_refuse(self):
        for fault in ('build-exit', 'build-output', 'bad-header'):
            with self.subTest(fault=fault): self.run_model(fault=fault)

    def test_missing_extra_wrong_order_or_partial_query_records_refuse(self):
        for fault in ('query-missing', 'query-extra', 'query-reversed', 'skipped-supplied-revocation'):
            with self.subTest(fault=fault): self.run_model(ed(2) + ed(3), fault=fault)

    def test_query_warning_error_and_excessive_records_refuse(self):
        for fault in ('query-warning', 'query-error', 'oversized-output'):
            with self.subTest(fault=fault): self.run_model(fault=fault)

    def test_private_query_snapshot_change_cannot_borrow_correct_membership(self):
        self.run_model(fault='mutated-query-input')

    def test_overlap_is_refused_after_complete_native_matching(self):
        self.run_model(overlap=True)

    def test_missing_tool_timeout_and_cleanup_failure_cannot_return_success(self):
        keys = KEYS.parse(ed())
        for error in (FileNotFoundError('fixture tool missing'), subprocess.TimeoutExpired('native', 10)):
            with mock.patch.object(KEYS.subprocess, 'run', side_effect=error):
                with self.assertRaises(type(error)): KEYS.native_revocations(keys, [])
        original = tempfile.TemporaryDirectory.cleanup
        def failed(instance): original(instance); raise OSError('fixture cleanup failed')
        with mock.patch.object(KEYS.tempfile.TemporaryDirectory, 'cleanup', failed):
            with self.assertRaisesRegex(OSError, 'cleanup failed'):
                self.run_model()


class NativeSSHRevocationTests(unittest.TestCase):
    def test_native_offline_parser_reports_declared_revoked_file_without_enforcement(self):
        directory, base, publics = self.fixture()
        spec = importlib.util.spec_from_file_location('s4_revoked_file_policy', ROOT / 'SSH/policy.py')
        policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
        candidate = policy.bundle(); content = candidate['files'][0]['content']; lines, substitutions = [], []
        key = base / 'fixture-0'
        for line in content.splitlines(keepends=True):
            if line.startswith('HostKey '):
                substitutions.append({'original': line.strip(), 'delivered': 'HostKey ' + str(key)})
                line = 'HostKey ' + str(key) + '\n'
            lines.append(line)
        self.assertEqual(len(substitutions), 2)
        delivered = ''.join(lines); config = base / 'sshd_config'; config.write_text(delivered); config.chmod(0o600)
        result = subprocess.run(['/usr/sbin/sshd', '-T', '-f', str(config)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertEqual(result.stderr, b'')
        values = [line for line in result.stdout.decode().splitlines() if line.startswith('revokedkeys ')]
        self.assertEqual(values, ['revokedkeys /etc/azurelinux3s4/ssh/admin_revoked_keys'])
        self.assertTrue(all(flag is False for flag in candidate['authority'].values()))
        record = {'candidate': candidate, 'delivered_config_sha256': hashlib.sha256(delivered.encode()).hexdigest(),
                  'hostkey_path_delivery_substitutions': substitutions, 'actual_parser_wait_exit': result.returncode,
                  'effective_stdout': result.stdout.decode(), 'effective_stderr': result.stderr.decode(),
                  'fixture_public_content': publics[0].decode(), 'native_sshd_revocation_enforced': False,
                  'private_bytes_retained': False, 'authentication_executed': False}
        directory.cleanup(); self.assertFalse(Path(directory.name).exists())
        self.record = {'owned_private_fixture_directory_removed': True, **record}

    def fixture(self):
        directory = tempfile.TemporaryDirectory(prefix='s4-native-revocation-', dir='/dev/shm')
        self.addCleanup(directory.cleanup)
        base = Path(directory.name); publics = []
        for index in range(3):
            key = base / ('fixture-' + str(index))
            result = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'owned-revocation-fixture', '-f', str(key)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertEqual(result.stdout + result.stderr, b'')
            publics.append(key.with_suffix('.pub').read_bytes())
        return directory, base, publics

    def observe(self, revoked_indices, delivered=False, expect_refusal=False, comment_only=False):
        directory, base, publics = self.fixture()
        source, revoked = base / 'source.pub', base / 'revoked.pub'
        source.write_bytes(publics[0] + publics[1]); source.chmod(0o600)
        revoked.write_bytes(b'# explicitly supplied empty list\n' if comment_only else b''.join(publics[index] for index in revoked_indices)); revoked.chmod(0o600)
        before = {str(path): KEYS.identity(path.stat()) for path in (source, revoked)}
        original = {str(path): path.read_bytes() for path in (source, revoked)}
        if delivered or expect_refusal:
            script = base / 'setup.sh'; script.write_bytes((ROOT / 'azurelinux3s4.sh').read_bytes()); script.chmod(0o755)
            result = subprocess.run([str(script), '--inspect-ssh-key-policy', str(source), str(revoked)], capture_output=True, cwd=base, timeout=15)
            self.assertEqual(result.returncode, 75 if expect_refusal else 0, result.stderr.decode())
            if expect_refusal:
                self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'SSH public-key inspection refused\n')
                proof = None
            else:
                self.assertEqual(result.stderr, b''); proof = json.loads(result.stdout)
        else:
            native_commands = []
            original_run = KEYS.subprocess.run
            def observed(command, **kwargs):
                names = ([command[3]] if command[1] == '-l' else [command[5]] if command[1] == '-k' else command[3:])
                inputs = {name: base64.b64encode(Path(name).read_bytes()).decode() for name in names}
                result = original_run(command, **kwargs)
                record = {'command': command, 'actual_wait_exit': result.returncode, 'input_base64': inputs,
                          'stdout_base64': base64.b64encode(Path(kwargs['stdout'].name).read_bytes()).decode(),
                          'stderr_base64': base64.b64encode(Path(kwargs['stderr'].name).read_bytes()).decode()}
                if command[1] == '-k': record['generated_krl_base64'] = base64.b64encode(Path(command[4]).read_bytes()).decode()
                native_commands.append(record)
                return result
            with mock.patch.object(KEYS.subprocess, 'run', side_effect=observed):
                proof = KEYS.inspect_policy(source, revoked)
            self.assertEqual(len(native_commands), 8 if revoked_indices else 7)
            self.assertEqual(sum(item['command'][1] == '-Q' for item in native_commands), 3)
            self.assertEqual(sum(item['command'][1] == '-k' for item in native_commands), 3)
        self.assertEqual({str(path): KEYS.identity(path.stat()) for path in (source, revoked)}, before)
        self.assertEqual({str(path): path.read_bytes() for path in (source, revoked)}, original)
        if proof:
            self.assertEqual(len(proof['authority']), 16)
            self.assertTrue(all(flag is False for flag in proof['authority'].values()))
            self.assertEqual(proof['sources']['candidate_keys']['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(proof['sources']['revocations']['sha256'], hashlib.sha256(revoked.read_bytes()).hexdigest())
            self.assertEqual(len(proof['candidate_fingerprints']), 2)
            self.assertEqual(len(proof['revoked_fingerprints']), len(revoked_indices))
            self.assertEqual(proof['explicit_empty_revocation_declaration'], not revoked_indices)
            self.assertEqual([entry['file'] for entry in proof['files']], ['ssh/admin_authorized_keys', 'ssh/admin_revoked_keys'])
            for entry in proof['files']:
                self.assertEqual(entry['mode'], '0600')
                self.assertEqual(entry['bytes'], len(entry['content'].encode()))
                self.assertEqual(entry['sha256'], hashlib.sha256(entry['content'].encode()).hexdigest())
            self.assertTrue(proof['files'][0]['content'].startswith('restrict,pty ssh-ed25519 '))
            if revoked_indices: self.assertTrue(proof['files'][1]['content'].startswith('ssh-ed25519 '))
            self.assertNotIn('restrict,pty', proof['files'][1]['content'])
            self.assertEqual([item['control'] for item in proof['native_comparison']], ['known-negative', 'known-positive', 'supplied'])
            self.assertEqual([item['actual_native_exit'] for item in proof['native_comparison']], [0, 1, int(bool(revoked_indices))])
            self.assertEqual(proof['native_comparison'][-1]['keys_compared'], 2 + len(revoked_indices))
            self.assertEqual(proof['native_comparison'][-1]['revoked_records'], len(revoked_indices))
        record = {'proof': proof, 'actual_cli_wait_exit': result.returncode if delivered or expect_refusal else None,
                  'source_public_content': source.read_text(), 'supplied_revocation_public_content': revoked.read_text(),
                  'source_content_metadata_unchanged': True, 'native_azure_policy_proven': False,
                  'private_bytes_retained': False, 'authentication_executed': False,
                  'native_commands': native_commands if not delivered and not expect_refusal else [],
                  'native_version': subprocess.run(['/usr/sbin/sshd', '-V'], capture_output=True, check=True).stderr.decode().strip()}
        directory.cleanup(); self.assertFalse(Path(directory.name).exists())
        self.record = {'owned_private_fixture_directory_removed': True, **record}

    def test_native_explicit_empty_revocation_and_both_participation_controls(self): self.observe([])

    def test_native_comment_only_revocation_is_an_explicit_empty_declaration(self): self.observe([], comment_only=True)

    def test_native_unrelated_revoked_key_is_verified_and_plain_bytes_bound(self): self.observe([2])

    def test_native_listed_candidate_refuses_all_cli_output(self): self.observe([1], expect_refusal=True)

    def test_native_delivered_policy_matches_without_checkout_or_host_preflight(self): self.observe([2], delivered=True)

    def test_native_missing_revocation_is_not_replaced_by_empty_policy(self):
        directory, base, publics = self.fixture(); source = base / 'source.pub'; source.write_bytes(publics[0]); source.chmod(0o600)
        result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-key-policy', str(source), str(base / 'missing')], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'SSH public-key inspection refused\n')
        self.assertFalse((base / 'missing').exists())
        directory.cleanup(); self.assertFalse(Path(directory.name).exists())
        self.record = {'actual_cli_wait_exit': 75, 'stdout_bytes': 0, 'missing_source_not_created': True,
                      'private_bytes_retained': False, 'authentication_executed': False, 'owned_private_fixture_directory_removed': True}

    def test_native_full_64_by_64_wire_model_batch_compares_every_key(self):
        with tempfile.TemporaryDirectory(prefix='s4-revocation-maximal-', dir='/dev/shm') as directory:
            source, revoked = Path(directory) / 'source', Path(directory) / 'revoked'
            source.write_bytes(b''.join(ed(seed) for seed in range(1, 65))); source.chmod(0o600)
            revoked.write_bytes(b''.join(ed(seed) for seed in range(65, 129))); revoked.chmod(0o600)
            proof = KEYS.inspect_policy(source, revoked)
            self.assertEqual(len(proof['candidate_fingerprints']), 64); self.assertEqual(len(proof['revoked_fingerprints']), 64)
            supplied = proof['native_comparison'][-1]
            self.assertEqual(supplied['keys_compared'], 128); self.assertEqual(supplied['revoked_records'], 64)
            self.assertEqual(supplied['actual_native_exit'], 1)
            self.assertTrue(all(flag is False for flag in proof['authority'].values()))
            record = {'proof': proof, 'wire_parameter_model_only': True, 'cryptographic_validity_proven': False,
                      'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'revocation_sha256': hashlib.sha256(revoked.read_bytes()).hexdigest(),
                      'private_bytes_retained': False, 'authentication_executed': False}
        self.assertFalse(Path(directory).exists()); self.record = {'owned_fixture_directory_removed': True, **record}


class SSHRevocationCLITests(unittest.TestCase):
    def test_policy_bound_covers_eight_leaf_allowances_and_preserves_old_bound(self):
        shell = (ROOT / 'SSH/keys.sh.in').read_text()
        self.assertIn('local seconds=30', shell)
        self.assertIn('[[ $# == 2 ]] && seconds=150', shell)
        self.assertEqual(8 * 10 + 70, 150)
        tree = __import__('ast').parse((ROOT / 'SSH/keys.py').read_text())
        policy = next(node for node in tree.body if isinstance(node, __import__('ast').FunctionDef) and node.name == 'inspect_policy')
        calls = [node for node in __import__('ast').walk(policy) if isinstance(node, __import__('ast').Call) and isinstance(node.func, __import__('ast').Name) and node.func.id == 'native_fingerprints']
        self.assertEqual(len(calls), 2)

    def test_policy_cli_requires_both_paths_and_rejects_extra_arguments(self):
        for arguments in ([], ['one'], ['one', 'two', 'extra']):
            result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-key-policy', *arguments], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64); self.assertEqual(result.stdout, b'')

    def test_private_revocation_input_is_not_echoed_or_repaired(self):
        with tempfile.TemporaryDirectory(prefix='s4-revocation-private-refusal-') as directory:
            source, revoked = Path(directory) / 'public', Path(directory) / 'private'
            source.write_bytes(ed()); source.chmod(0o600)
            data = b'-----BEGIN OPENSSH PRIVATE KEY-----\nDO-NOT-ECHO-PRIVATE-INPUT\n'
            revoked.write_bytes(data); revoked.chmod(0o600)
            result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-key-policy', str(source), str(revoked)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'SSH public-key inspection refused\n')
            self.assertEqual(revoked.read_bytes(), data)


if __name__ == '__main__': unittest.main()

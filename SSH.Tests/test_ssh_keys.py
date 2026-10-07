import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('s4_ssh_keys', ROOT / 'SSH/keys.py')
KEYS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KEYS)


def string(value):
    return struct.pack('>I', len(value)) + value


def entry(blob, kind=b'ssh-ed25519'):
    return kind + b' ' + base64.b64encode(blob) + b' fixture-comment\n'


def ed(seed=1):
    return entry(string(b'ssh-ed25519') + string(bytes([seed]) * 32))


def mpint(value):
    data = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return (b'\0' if data[0] & 128 else b'') + data


def rsa(bits=3072, exponent=65537):
    # Parameter/decoder model, not a genuine generated RSA key or native proof.
    return entry(string(b'ssh-rsa') + string(mpint(exponent))
                 + string(mpint((1 << (bits - 1)) | 1)), b'ssh-rsa')


class SSHKeyFormatTests(unittest.TestCase):
    def test_bare_ed_and_rsa_parameters_emit_only_restricted_prospective_entries(self):
        values = KEYS.parse(ed() + rsa())
        self.assertEqual([(key['type'], key['bits']) for key in values], [('ssh-ed25519', 256), ('ssh-rsa', 3072)])
        for key in values:
            self.assertTrue(key['entry'].startswith('restrict,pty ' + key['type'] + ' '))
            self.assertTrue(key['entry'].endswith(' azurelinux3s4-candidate\n'))
            self.assertNotIn('fixture-comment', key['entry'])

    def test_comments_and_blank_lines_do_not_become_candidate_key_options(self):
        key = ed()
        self.assertEqual(KEYS.parse(b'# irrelevant\n \t\n\t' + key + b'\n'), KEYS.parse(key))

    def test_derived_fingerprint_binds_exact_decoded_wire_bytes(self):
        data = ed()
        blob = base64.b64decode(data.split()[1])
        expected = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        self.assertEqual(KEYS.parse(data)[0]['fingerprint'], expected)

    def test_source_options_and_forced_commands_refuse_instead_of_being_stripped(self):
        for prefix in (b'restrict ', b'from="10.0.0.0/8" ', b'command="/bin/true" ', b'cert-authority ', b'no-pty '):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError): KEYS.parse(prefix + ed())

    def test_certificates_security_keys_dsa_ecdsa_and_private_material_refuse(self):
        for kind in (b'ssh-ed25519-cert-v01@openssh.com', b'sk-ssh-ed25519@openssh.com', b'ssh-dss', b'ecdsa-sha2-nistp256'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                KEYS.parse(entry(string(kind) + string(b'a' * 32), kind))
        for data in (b'-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n', b'-----BEGIN RSA PRIVATE KEY-----\nsecret\n'):
            with self.assertRaises(ValueError): KEYS.parse(data)

    def test_empty_comment_only_control_bytes_non_ascii_and_missing_final_lf_refuse(self):
        for data in (b'', b'# only\n', ed().rstrip(b'\n'), ed() + b'\r\n', ed() + b'\0\n', ed() + b'\x1b\n', ed() + b'\x7f\n', ed() + b'\xff\n'):
            with self.subTest(data=data[-10:]), self.assertRaises(ValueError): KEYS.parse(data)

    def test_invalid_and_noncanonical_base64_refuse(self):
        token = ed().split()[1]
        self.assertFalse(token.endswith(b'='))
        for value in (b'@', token[:-1], token + b'=', b'A==='):
            with self.subTest(value=value[-8:]), self.assertRaises(ValueError): KEYS.parse(b'ssh-ed25519 ' + value + b'\n')
        # A canonical RSA blob has padding; alter only unused pad bits.
        padded = rsa().split()[1]
        self.assertTrue(padded.endswith(b'='))
        self.assertFalse(padded.endswith(b'=='))
        alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        changed = padded[:-2] + bytes([alphabet[alphabet.index(padded[-2]) + 1]]) + b'='
        self.assertEqual(base64.b64decode(padded), base64.b64decode(changed))
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            KEYS.parse(b'ssh-rsa ' + changed + b'\n')
        with self.assertRaises(ValueError): KEYS.parse(b'ssh-rsa ' + padded.rstrip(b'=') + b'\n')

    def test_truncated_lengths_oversized_fields_and_trailing_wire_refuse(self):
        blob = base64.b64decode(ed().split()[1])
        for value in (blob[:2], blob[:-1], blob + b'\0', struct.pack('>I', 2**32 - 1) + b'key', string(b'ssh-ed25519') + string(b'')):
            with self.subTest(size=len(value)), self.assertRaises(ValueError): KEYS.parse(entry(value))

    def test_text_wire_type_mismatch_and_ed_length_refuse(self):
        for value in (string(b'ssh-rsa') + string(b'a' * 32), string(b'ssh-ed25519') + string(b'a' * 33)):
            with self.assertRaises(ValueError): KEYS.parse(entry(value))

    def test_rsa_weak_exponent_even_modulus_and_size_bounds_refuse(self):
        for data in (rsa(2048), rsa(8193), rsa(3072, 3), entry(string(b'ssh-rsa') + string(mpint(65537))
                       + string(mpint(1 << 3071)), b'ssh-rsa')):
            with self.assertRaises(ValueError): KEYS.parse(data)
        self.assertEqual(KEYS.parse(rsa(8192))[0]['bits'], 8192)

    def test_rsa_negative_zero_and_redundant_mpints_refuse(self):
        for exponent in (b'\x80', b'\0', b'\0\x01\0\x01'):
            with self.assertRaises(ValueError):
                KEYS.parse(entry(string(b'ssh-rsa') + string(exponent) + string(mpint((1 << 3071) | 1)), b'ssh-rsa'))
        for modulus in (b'\x80' + b'\0' * 383, b'\0\0\x80' + b'\0' * 381 + b'\x01'):
            with self.assertRaises(ValueError):
                KEYS.parse(entry(string(b'ssh-rsa') + string(mpint(65537)) + string(modulus), b'ssh-rsa'))

    def test_duplicate_key_with_different_comment_refuses(self):
        with self.assertRaises(ValueError): KEYS.parse(ed() + ed().replace(b'fixture-comment', b'other'))

    def test_key_line_source_and_total_line_bounds_refuse(self):
        for data in (b''.join(ed(seed) for seed in range(1, 66)), ed() + b'#' * 8193 + b'\n',
                     b'#\n' * 4097 + ed(), b'#' * (KEYS.SOURCE_LIMIT + 1) + b'\n'):
            with self.assertRaises(ValueError): KEYS.parse(data)
        self.assertEqual(len(KEYS.parse(b''.join(ed(seed) for seed in range(1, 65)))), 64)

    def test_partial_valid_batch_with_invalid_key_withholds_entire_result(self):
        with self.assertRaises(ValueError): KEYS.parse(ed() + b'ssh-ed25519 broken\n')


class SSHKeySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='s4-key-source-')
        self.base = Path(self.directory.name)
        self.path = self.base / 'source.pub'
        self.path.write_bytes(ed())
        self.path.chmod(0o644)
        self.addCleanup(self.directory.cleanup)

    def test_public_regular_0644_and_0600_sources_are_observed_without_mutation(self):
        for mode in (0o644, 0o600):
            self.path.chmod(mode)
            before = KEYS.identity(self.path.stat())
            self.assertEqual(KEYS.snapshot(self.path), ed())
            self.assertEqual(KEYS.identity(self.path.stat()), before)

    def test_fifo_socket_directory_symlink_and_device_refuse_before_open(self):
        fifo, link, directory, endpoint = (self.base / name for name in ('fifo', 'link', 'directory', 'socket'))
        os.mkfifo(fifo, 0o600)
        link.symlink_to(self.path)
        directory.mkdir()
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(endpoint))
            before = {str(path): KEYS.identity(path.lstat()) for path in (fifo, link, directory, endpoint)}
            for path in (fifo, link, directory, endpoint, Path('/dev/null')):
                with self.subTest(path=path), mock.patch.object(KEYS.os, 'open', side_effect=AssertionError('must not open')):
                    with self.assertRaises(ValueError): KEYS.snapshot(path)
            self.assertEqual({str(path): KEYS.identity(path.lstat()) for path in (fifo, link, directory, endpoint)}, before)

    def test_group_or_world_writable_regular_sources_refuse(self):
        for mode in (0o620, 0o602, 0o666):
            self.path.chmod(mode)
            with mock.patch.object(KEYS.os, 'open', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError): KEYS.snapshot(self.path)
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), mode)

    def test_foreign_owner_delivery_refuses_before_open(self):
        with mock.patch.object(KEYS.os, 'geteuid', return_value=os.geteuid() + 1), mock.patch.object(KEYS.os, 'open', side_effect=AssertionError('must not open')):
            with self.assertRaises(ValueError): KEYS.snapshot(self.path)

    def test_empty_and_excessive_regular_files_refuse_before_open(self):
        for size in (0, KEYS.SOURCE_LIMIT + 1):
            with self.path.open('wb') as stream: stream.truncate(size)
            with mock.patch.object(KEYS.os, 'open', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError): KEYS.snapshot(self.path)

    def test_open_requires_nofollow_cloexec_and_nonblock(self):
        original = KEYS.os.open
        def observed(path, flags):
            self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            return original(path, flags)
        with mock.patch.object(KEYS.os, 'open', side_effect=observed):
            self.assertEqual(KEYS.snapshot(self.path), ed())

    def test_race_to_fifo_is_bounded_and_refused_before_read(self):
        original = KEYS.os.open
        def raced(path, flags):
            self.path.unlink()
            os.mkfifo(self.path, 0o600)
            return original(path, flags)
        with mock.patch.object(KEYS.os, 'open', side_effect=raced), mock.patch.object(KEYS.os, 'read', side_effect=AssertionError('must not read FIFO')):
            with self.assertRaisesRegex(ValueError, 'before snapshot'): KEYS.snapshot(self.path)
        self.assertTrue(stat.S_ISFIFO(self.path.lstat().st_mode))

    def test_path_replacement_after_open_does_not_read_replacement(self):
        original = KEYS.os.read
        replacement = self.base / 'replacement'
        replacement.write_bytes(ed(2)); replacement.chmod(0o644)
        def raced(fd, count):
            if replacement.exists(): os.replace(replacement, self.path)
            return original(fd, count)
        with mock.patch.object(KEYS.os, 'read', side_effect=raced):
            with self.assertRaisesRegex(ValueError, 'during snapshot'): KEYS.snapshot(self.path)
        self.assertEqual(self.path.read_bytes(), ed(2))

    def test_observed_same_inode_metadata_change_during_read_refuses(self):
        original = KEYS.os.read
        changed = False
        def raced(fd, count):
            nonlocal changed
            if not changed:
                changed = True
                before = self.path.stat()
                self.path.write_bytes(ed(2))
                os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
                self.assertEqual(self.path.stat().st_ino, before.st_ino)
                self.assertNotEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
            return original(fd, count)
        with mock.patch.object(KEYS.os, 'read', side_effect=raced):
            with self.assertRaisesRegex(ValueError, 'during snapshot'): KEYS.snapshot(self.path)

    def test_growth_crossing_snapshot_limit_refuses(self):
        with mock.patch.object(KEYS.os, 'read', side_effect=[b'x' * KEYS.SOURCE_LIMIT, b'y']):
            with self.assertRaisesRegex(ValueError, 'exceeds snapshot bound'): KEYS.snapshot(self.path)

    def test_descriptor_close_failure_cannot_return_success(self):
        original = KEYS.os.close
        def failed(fd):
            original(fd)
            raise OSError('delivered close failure')
        with mock.patch.object(KEYS.os, 'close', side_effect=failed):
            with self.assertRaisesRegex(OSError, 'close failure'): KEYS.snapshot(self.path)


class SSHKeyNativeDeliveryTests(unittest.TestCase):
    def delivery(self, result=0, output=None, errors=b'', damaged=False):
        keys = KEYS.parse(ed())
        content = keys[0]['entry'].encode()
        expected = ('256 ' + keys[0]['fingerprint'] + ' ' + KEYS.COMMENT + ' (ED25519)\n').encode()
        folders = []
        def run(command, **kwargs):
            candidate = Path(command[3]); folders.append(candidate.parent)
            self.assertEqual(command, ['/usr/bin/ssh-keygen', '-l', '-f', str(candidate), '-E', 'sha256'])
            self.assertEqual(candidate.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(candidate.parent.stat().st_mode), 0o700)
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(kwargs['timeout'], 10)
            if damaged: candidate.write_bytes(b'delivered corrupt input\n')
            kwargs['stdout'].write(expected if output is None else output)
            kwargs['stderr'].write(errors)
            return subprocess.CompletedProcess(command, result)
        return keys, content, run, folders, expected

    def test_complete_native_records_and_private_snapshot_delivery(self):
        keys, content, run, folders, _ = self.delivery()
        with mock.patch.object(KEYS.subprocess, 'run', side_effect=run): KEYS.native_fingerprints(content, keys)
        self.assertEqual(len(folders), 1)
        self.assertFalse(folders[0].exists())

    def test_exit_zero_without_exact_fingerprint_records_refuses(self):
        for output in (b'', b'256 SHA256:foreign azurelinux3s4-candidate (ED25519)\n', b'2048 SHA256:foreign (RSA)\n'):
            keys, content, run, folders, _ = self.delivery(output=output)
            with mock.patch.object(KEYS.subprocess, 'run', side_effect=run):
                with self.assertRaises(ValueError): KEYS.native_fingerprints(content, keys)
            self.assertFalse(folders[0].exists())

    def test_native_extra_duplicate_or_truncated_records_refuse(self):
        keys, content, _, _, expected = self.delivery()
        for output in (expected * 2, expected + b'foreign\n', expected.rstrip(b'\n')):
            _, _, run, _, _ = self.delivery(output=output)
            with mock.patch.object(KEYS.subprocess, 'run', side_effect=run):
                with self.assertRaises(ValueError): KEYS.native_fingerprints(content, keys)

    def test_native_reordered_batch_records_refuse(self):
        keys = KEYS.parse(ed(1) + ed(2))
        content = ''.join(key['entry'] for key in keys).encode()
        expected = ''.join('256 ' + key['fingerprint'] + ' ' + KEYS.COMMENT + ' (ED25519)\n' for key in reversed(keys)).encode()
        def run(command, **kwargs):
            self.assertEqual(Path(command[3]).read_bytes(), content)
            kwargs['stdout'].write(expected)
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(KEYS.subprocess, 'run', side_effect=run):
            with self.assertRaises(ValueError): KEYS.native_fingerprints(content, keys)

    def test_mutated_private_candidate_cannot_borrow_correct_native_records(self):
        keys, content, run, folders, _ = self.delivery(damaged=True)
        with mock.patch.object(KEYS.subprocess, 'run', side_effect=run):
            with self.assertRaises(ValueError): KEYS.native_fingerprints(content, keys)
        self.assertFalse(folders[0].exists())

    def test_nonzero_exit_warning_and_excessive_native_outputs_refuse(self):
        for kwargs in ({'result': 1}, {'errors': b'warning\n'}, {'output': b'x' * 16385}, {'errors': b'x' * 8193}):
            keys, content, run, folders, _ = self.delivery(**kwargs)
            with mock.patch.object(KEYS.subprocess, 'run', side_effect=run):
                with self.assertRaises(ValueError): KEYS.native_fingerprints(content, keys)
            self.assertFalse(folders[0].exists())

    def test_missing_native_tool_and_timeout_refuse_and_cleanup(self):
        keys, content, _, _, _ = self.delivery()
        for error in (FileNotFoundError('missing native'), subprocess.TimeoutExpired('native', 10)):
            with mock.patch.object(KEYS.subprocess, 'run', side_effect=error):
                with self.assertRaises(type(error)): KEYS.native_fingerprints(content, keys)

    def test_temporary_cleanup_failure_withholds_result(self):
        keys, content, run, _, _ = self.delivery()
        original = tempfile.TemporaryDirectory.cleanup
        def failed(instance):
            original(instance)
            raise OSError('delivered cleanup failure')
        with mock.patch.object(KEYS.subprocess, 'run', side_effect=run), mock.patch.object(KEYS.tempfile.TemporaryDirectory, 'cleanup', failed):
            with self.assertRaisesRegex(OSError, 'cleanup failure'): KEYS.native_fingerprints(content, keys)


class NativeSSHKeyTests(unittest.TestCase):
    def fixture(self, kinds):
        directory = tempfile.TemporaryDirectory(prefix='s4-key-native-', dir='/dev/shm')
        self.addCleanup(directory.cleanup)
        base = Path(directory.name)
        sources, records = [], []
        for index, kind in enumerate(kinds):
            key = base / ('fixture_' + str(index))
            command = ['/usr/bin/ssh-keygen', '-q', '-t', kind, '-N', '', '-C', 'owned-public-fixture', '-f', str(key)]
            if kind == 'rsa': command += ['-b', '3072']
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout + result.stderr, b'')
            data = key.with_suffix('.pub').read_bytes()
            sources.append(data)
            records.append({'keygen_wait_exit': 0, 'kind': kind, 'public_sha256': hashlib.sha256(data).hexdigest(), 'public_content': data.decode()})
        source = base / 'input.pub'; source.write_bytes(b''.join(sources)); source.chmod(0o644)
        return directory, source, records

    def observe(self, kinds, delivered=False):
        directory, source, generated = self.fixture(kinds)
        before = KEYS.identity(source.stat())
        original = source.read_bytes()
        if delivered:
            standalone = Path(directory.name) / 'setup.sh'
            standalone.write_bytes((ROOT / 'azurelinux3s4.sh').read_bytes()); standalone.chmod(0o755)
            result = subprocess.run([str(standalone), '--inspect-ssh-keys', str(source)], cwd=directory.name,
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            proof = json.loads(result.stdout)
        else:
            proof = KEYS.inspect(source)
        self.assertEqual(KEYS.identity(source.stat()), before)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(proof['source_sha256'], hashlib.sha256(original).hexdigest())
        candidate = proof['candidate']
        self.assertEqual(candidate['bytes'], len(candidate['content'].encode()))
        self.assertEqual(candidate['sha256'], hashlib.sha256(candidate['content'].encode()).hexdigest())
        self.assertEqual(len(proof['authority']), 15)
        self.assertTrue(all(flag is False for flag in proof['authority'].values()))
        self.assertEqual(len(proof['keys']), len(kinds))
        self.assertNotIn('owned-public-fixture', candidate['content'])
        self.assertEqual([key['type'] for key in proof['keys']], ['ssh-' + kind for kind in kinds])
        # An independent native list over original PUBLIC bytes must correspond.
        checked = subprocess.run(['/usr/bin/ssh-keygen', '-l', '-f', str(source), '-E', 'sha256'], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertEqual(checked.stderr, b'')
        self.assertEqual([(int(line.split()[0]), line.split()[1]) for line in checked.stdout.decode().splitlines()],
                         [(key['bits'], key['fingerprint']) for key in proof['keys']])
        record = {'generated_public_fixtures': generated, 'proof': proof, 'actual_independent_fingerprint_wait_exit': checked.returncode,
                  'independent_source_fingerprint_stdout': checked.stdout.decode(), 'standalone_delivery': delivered,
                  'native_tool_version': subprocess.run(['/usr/sbin/sshd', '-V'], capture_output=True, check=True).stderr.decode().strip(),
                  'source_metadata_unchanged': True, 'private_bytes_retained': False, 'authentication_executed': False,
                  'accounts_created': False, 'production_keys_provisioned': False, 'native_azure_policy_proven': False}
        directory.cleanup()
        self.assertFalse(Path(directory.name).exists())
        self.record = {'owned_private_fixture_directory_removed': True, **record}

    def test_native_ed25519_public_snapshot_matches_exact_fingerprints(self):
        self.observe(['ed25519'])

    def test_native_rsa3072_and_ed25519_batch_matches_exact_fingerprints(self):
        self.observe(['rsa', 'ed25519'])

    def test_standalone_delivered_inspection_matches_without_checkout_or_host_preflight(self):
        self.observe(['ed25519'], delivered=True)

    def test_native_valid_then_damaged_batch_refuses_without_partial_json(self):
        directory, source, generated = self.fixture(['ed25519'])
        source.write_bytes(source.read_bytes() + b'ssh-ed25519 AAAA\n')
        original = source.read_bytes()
        result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-keys', str(source)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'SSH public-key inspection refused\n')
        self.assertEqual(source.read_bytes(), original)
        directory.cleanup(); self.assertFalse(Path(directory.name).exists())
        self.record = {'generated_public_fixtures': generated, 'actual_inspection_wait_exit': 75, 'stdout_bytes': 0,
                      'stderr': result.stderr.decode(), 'source_unchanged': True, 'owned_private_fixture_directory_removed': True,
                      'authentication_executed': False, 'private_bytes_retained': False}

    def test_native_maximum_rsa_parameter_model_batch_emits_to_regular_output(self):
        # Large syntactic RSA values are NOT genuine key generation/prime proof.
        with tempfile.TemporaryDirectory(prefix='s4-key-maximal-', dir='/dev/shm') as directory:
            base = Path(directory)
            source = base / 'models.pub'
            blobs = [string(b'ssh-rsa') + string(mpint(65537))
                     + string(mpint((1 << 8191) | (index * 2 + 1))) for index in range(64)]
            data = b''.join(entry(blob, b'ssh-rsa') for blob in blobs)
            source.write_bytes(data); source.chmod(0o600)
            output = base / 'output.json'
            with output.open('wb') as stream:
                result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-keys', str(source)],
                                        stdout=stream, stderr=subprocess.PIPE, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            proof = json.loads(output.read_bytes())
            self.assertEqual(len(proof['keys']), 64)
            self.assertEqual([key['bits'] for key in proof['keys']], [8192] * 64)
            self.assertEqual(proof['source_sha256'], hashlib.sha256(data).hexdigest())
            self.assertGreater(output.stat().st_size, 65536)
            self.assertLess(output.stat().st_size, 512 * 1024)
            self.assertTrue(all(flag is False for flag in proof['authority'].values()))
            record = {'actual_inspection_wait_exit': result.returncode, 'stderr': result.stderr.decode(),
                      'source_sha256': hashlib.sha256(data).hexdigest(), 'source_bytes': len(data),
                      'regular_output_bytes': output.stat().st_size, 'regular_output_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                      'keys': proof['keys'], 'authority': proof['authority'], 'rsa_parameter_model_only': True,
                      'cryptographic_validity_proven': False, 'authentication_executed': False, 'private_bytes_retained': False}
        self.assertFalse(Path(directory).exists())
        self.record = {'owned_directory_removed': True, **record}

    def test_actual_fifo_cli_refuses_without_blocking_or_mutating_operator_object(self):
        with tempfile.TemporaryDirectory(prefix='s4-key-native-fifo-', dir='/dev/shm') as directory:
            source = Path(directory) / 'operator.fifo'; os.mkfifo(source, 0o600)
            before = KEYS.identity(source.lstat())
            result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-keys', str(source)], capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 75)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'SSH public-key inspection refused\n')
            self.assertEqual(KEYS.identity(source.lstat()), before)
            record = {'actual_inspection_wait_exit': 75, 'stdout_bytes': 0, 'stderr': result.stderr.decode(),
                      'real_fifo_preserved': True, 'two_second_outer_limit': True, 'authentication_executed': False, 'private_bytes_retained': False}
        self.assertFalse(Path(directory).exists())
        self.record = {'owned_directory_removed': True, **record}


class SSHKeyCLITests(unittest.TestCase):
    def test_wrong_argument_count_refuses_without_output(self):
        for command in ([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-keys'],
                        [str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-keys', 'source', 'extra'],
                        [sys.executable, '-I', str(ROOT / 'SSH/keys.py')]):
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout, b'')

    def test_private_input_is_not_echoed_on_refusal(self):
        with tempfile.TemporaryDirectory(prefix='s4-key-mistaken-private-') as directory:
            source = Path(directory) / 'input'
            secret = b'PRIVATE-FIXTURE-SHOULD-NEVER-BE-ECHOED'
            source.write_bytes(b'-----BEGIN OPENSSH PRIVATE KEY-----\n' + secret + b'\n')
            source.chmod(0o600)
            result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-keys', str(source)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 75)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'SSH public-key inspection refused\n')
            self.assertNotIn(secret, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load('service_fixture_policy', 'SSH/policy.py')
SERVICE = load('service_fixture_compiler', 'SSH/service.py')


def unit(candidate):
    return candidate['files'][1]['content']


class SSHServiceTests(unittest.TestCase):
    def candidate(self):
        return SERVICE.service_bundle(POLICY.bundle)

    def test_configuration_is_entire_unchanged_accepted_producer_output(self):
        candidate = self.candidate()
        self.assertEqual(candidate['ssh_policy'], POLICY.bundle())
        self.assertEqual(candidate['files'][0], POLICY.bundle()['files'][0])
        self.assertEqual(candidate['configuration_sha256'], candidate['files'][0]['sha256'])
        self.assertEqual(candidate['ssh_policy']['listen_addresses'], ['127.0.0.1', '::1'])

    def test_all_files_bytes_names_modes_and_digests_are_bound(self):
        candidate = self.candidate()
        self.assertEqual([entry['file'] for entry in candidate['files']],
                         ['ssh/sshd_config', 'azurelinux3s4-sshd.service'])
        for entry in candidate['files']:
            data = entry['content'].encode('ascii')
            self.assertEqual(entry['mode'], '0644')
            self.assertEqual(entry['bytes'], len(data))
            self.assertEqual(entry['sha256'], hashlib.sha256(data).hexdigest())
            self.assertTrue(data.endswith(b'\n'))

    def test_check_and_daemon_have_fixed_exact_arguments_without_overrides(self):
        candidate = self.candidate()
        values = {line.split('=', 1)[0]: line.split('=', 1)[1]
                  for line in unit(candidate).split('\n') if '=' in line}
        self.assertEqual(shlex.split(values['ExecStartPre']),
                         ['/usr/sbin/sshd', '-t', '-f', '/etc/azurelinux3s4/ssh/sshd_config'])
        self.assertEqual(shlex.split(values['ExecStart']),
                         ['/usr/sbin/sshd', '-D', '-e', '-f', '/etc/azurelinux3s4/ssh/sshd_config'])
        self.assertEqual(candidate['check_argv'], shlex.split(values['ExecStartPre']))
        self.assertEqual(candidate['daemon_argv'], shlex.split(values['ExecStart']))
        self.assertEqual(values['Type'], 'exec')
        for name in ('ExecCondition', 'ExecReload', 'EnvironmentFile', 'PIDFile'):
            self.assertNotIn(name, values)
        for value in (values['ExecStart'], values['ExecStartPre']):
            self.assertNotIn('-o', value)
            self.assertNotIn('$', value)
            self.assertNotIn('%', value)
            self.assertNotIn('/bin/sh', value)
            self.assertFalse(value.startswith(('-', '+', '!', '@', ':')))

    def test_retry_limits_do_not_gate_on_current_files_or_network_online(self):
        content = unit(self.candidate())
        for line in ('Restart=always', 'RestartSec=30s', 'StartLimitIntervalSec=0',
                     'TimeoutStartSec=60s', 'TimeoutStopSec=30s', 'After=network.target'):
            self.assertEqual(content.split('\n').count(line), 1)
        self.assertNotIn('Condition', content)
        self.assertNotIn('network-online.target', content)
        self.assertNotIn('RestartPreventExitStatus', content)

    def test_prospective_security_and_cleanup_declarations_have_false_authority(self):
        candidate = self.candidate()
        for line in ('NoNewPrivileges=yes', 'UMask=0077', 'LimitCORE=0', 'KillMode=control-group',
                     'StandardInput=null', 'StandardOutput=journal', 'StandardError=journal'):
            self.assertIn(line + '\n', unit(candidate))
        self.assertEqual(len(candidate['authority']), 18)
        self.assertTrue(all(value is False for value in candidate['authority'].values()))
        self.assertEqual(len(candidate['ssh_policy']['authority']), 15)
        self.assertTrue(all(value is False for value in candidate['ssh_policy']['authority'].values()))
        self.assertTrue(all(value is False for value in candidate['ssh_policy']['cryptography']['authority'].values()))

    def test_native_runtime_pam_boot_continuity_and_privilege_limits_are_explicit(self):
        text = ' '.join(self.candidate()['limits'] + self.candidate()['prerequisites'])
        for expected in ('not listening', 'PAM/LSM', 'root daemon existing privileges', 'No sudo package removal',
                         'SAME configuration/service bytes', 'drop-ins', 'races/ABA', 'explicit manager stop',
                         'privilege-separation-directory', 'no actual manager/cgroup/session cleanup'):
            self.assertIn(expected, text)

    def test_wrong_type_name_sources_or_claimed_authority_refuse(self):
        for replacement in (None, [], 'policy', {'admin_account_name': 'root'},
                            {'source_prefixes': ['10.0.0.0/8']}, {'listen_addresses': ['0.0.0.0']},
                            {'authority': {'installation_authorized': False}}, {'files': {}}):
            candidate = POLICY.bundle()
            if isinstance(replacement, dict): candidate.update(replacement)
            else: candidate = replacement
            with self.subTest(value=replacement), self.assertRaises(ValueError):
                SERVICE.service_bundle(lambda: candidate)
        for claim in (True, 0, None, 'false'):
            candidate = POLICY.bundle(); candidate['authority']['installation_authorized'] = claim
            with self.subTest(claim=claim), self.assertRaises(ValueError):
                SERVICE.service_bundle(lambda: candidate)

    def test_missing_duplicate_or_wrong_kind_file_declarations_refuse(self):
        for files in ([], [None], [POLICY.bundle()['files'][0]] * 2, ['configuration']):
            candidate = POLICY.bundle(); candidate['files'] = files
            with self.subTest(files=files), self.assertRaises(ValueError):
                SERVICE.service_bundle(lambda: candidate)
        for changes in ({'file': '../sshd_config'}, {'file': '/etc/sshd_config'}, {'mode': '0600'},
                        {'content': None}, {'bytes': True}, {'bytes': 0}, {'sha256': '0' * 64}):
            candidate = POLICY.bundle(); candidate['files'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                SERVICE.service_bundle(lambda: candidate)

    def test_control_non_ascii_unterminated_or_excessive_config_refuses(self):
        for content in ('', 'Port 22', 'Port 22\r\n', 'Port 22\x00\n', 'Port 22\u2028\n',
                        'x' * SERVICE.SERVICE_CONFIG_LIMIT + '\n', 'Port\t22\n', 'Port 22\x7f\n'):
            candidate = POLICY.bundle(); entry = candidate['files'][0]
            entry.update(content=content, bytes=len(content.encode()), sha256=hashlib.sha256(content.encode()).hexdigest())
            with self.subTest(content=repr(content[:20])), self.assertRaises(ValueError):
                SERVICE.service_bundle(lambda: candidate)

    def test_configuration_is_copied_without_mutating_accepted_policy(self):
        policy = POLICY.bundle(); before = copy.deepcopy(policy)
        candidate = SERVICE.service_bundle(lambda: policy)
        self.assertEqual(policy, before)
        self.assertIsNot(candidate['files'][0], policy['files'][0])

    def test_composed_executable_policy_globals_are_exact_except_docstring(self):
        namespace = {'__name__': 's4_ssh_candidate_library'}
        exec(compile((ROOT / 'SSH/policy.py').read_bytes(), 'policy.py', 'exec'), namespace)
        before = dict(namespace)
        exec(compile((ROOT / 'SSH/service.py').read_bytes(), 'service.py', 'exec'), namespace)
        for name, value in before.items():
            if name != '__doc__': self.assertIs(namespace[name], value, name)
        self.assertEqual(namespace['bundle'](), POLICY.bundle())

    def test_main_failure_withholds_all_json_and_uses_fixed_refusal(self):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['fixture']), patch.object(SERVICE.resource, 'setrlimit'), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = SERVICE.service_main(lambda: {})
        self.assertEqual(code, 75)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(error.getvalue(), 'SSH service candidate refused\n')

    def test_main_argument_refusal_precedes_producer_or_resource_work(self):
        with patch.object(sys, 'argv', ['fixture', 'override']), \
                patch.object(SERVICE.resource, 'setrlimit', side_effect=AssertionError('resource work')):
            self.assertEqual(SERVICE.service_main(lambda: self.fail('producer called')), 64)


class SSHServiceCLITests(unittest.TestCase):
    def test_standalone_service_delivery_has_exact_bytes_without_checkout_or_preflight(self):
        with tempfile.TemporaryDirectory(prefix='s4-ssh-service-delivery-') as directory:
            delivered = Path(directory) / 'setup.sh'
            delivered.write_bytes((ROOT / 'azurelinux3s4.sh').read_bytes()); delivered.chmod(0o755)
            result = subprocess.run([str(delivered), '--ssh-service-policy'], cwd=directory,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            self.assertEqual(json.loads(result.stdout), SERVICE.service_bundle(POLICY.bundle))
            self.assertEqual(list(Path(directory).iterdir()), [delivered])

    def test_service_argument_refusal_has_no_json_or_created_files(self):
        with tempfile.TemporaryDirectory(prefix='s4-ssh-service-args-') as directory:
            result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--ssh-service-policy', 'override'],
                                    cwd=directory, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout + result.stderr, b'')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_existing_configuration_cli_output_is_unchanged(self):
        result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--ssh-policy'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), POLICY.bundle())

    def test_invalid_internal_dispatch_never_calls_native_or_preflight(self):
        script = 'source "$1"; s4_preflight() { return 91; }; s4_ssh_candidate invalid'
        result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'azurelinux3s4.sh')],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout + result.stderr, b'')

    def test_service_branch_precedes_host_preflight_state_and_lock(self):
        script = ('source "$1"; s4_preflight() { return 91; }; s4_prepare_state() { return 92; }; '
                  's4_lock() { return 93; }; s4_main --ssh-service-policy')
        result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'azurelinux3s4.sh')],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), SERVICE.service_bundle(POLICY.bundle))


class NativeSSHServiceTests(unittest.TestCase):
    def verify_unit(self, content):
        with tempfile.TemporaryDirectory(prefix='s4-ssh-unit-') as directory:
            source = Path(directory) / SERVICE.SERVICE_NAME
            source.write_text(content); source.chmod(0o644)
            command = ['/usr/bin/systemd-analyze', '--man=no', 'verify', str(source)]
            result = subprocess.run(command, capture_output=True, timeout=15,
                                    env={**os.environ, 'SYSTEMD_COLORS': '0', 'SYSTEMD_LOG_LEVEL': 'warning'})
            receipt = {'command': command, 'delivered_unit_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                       'delivered_unit_content': content, 'actual_child_wait_exit': result.returncode,
                       'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()}
        self.assertFalse(Path(directory).exists())
        return result, {**receipt, 'owned_fixture_directory_removed': True}

    def test_native_offline_parser_accepts_entire_unit_without_executable_substitution(self):
        candidate = SERVICE.service_bundle(POLICY.bundle)
        result, record = self.verify_unit(unit(candidate))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout + result.stderr, b'')
        self.record = {**record, 'candidate': candidate, 'unit_content_substitution': False,
                       'manager_or_daemon_activated': False, 'native_azure_policy_proven': False}

    def test_native_offline_unit_parser_does_not_admit_ssh_argument_semantics_model(self):
        candidate = SERVICE.service_bundle(POLICY.bundle)
        original = 'ExecStart=' + ' '.join(candidate['daemon_argv']) + '\n'
        changed = original.rstrip('\n') + ' -oPermitRootLogin=yes\n'
        content = unit(candidate)
        self.assertEqual(content.count(original), 1)
        result, record = self.verify_unit(content.replace(original, changed))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout + result.stderr, b'')
        self.record = {**record, 'scope': 'EXPLICIT argv-override MODEL; not shipped candidate',
                       'sole_edit': {'original': original, 'delivered': changed},
                       'unit_parser_does_not_validate_ssh_semantics': True, 'manager_or_daemon_activated': False}

    def test_native_check_only_invocation_on_private_hostkey_path_delivery(self):
        candidate = SERVICE.service_bundle(POLICY.bundle)
        source = candidate['files'][0]
        with tempfile.TemporaryDirectory(prefix='s4-ssh-check-', dir='/dev/shm') as directory:
            key = Path(directory) / 'fixture_ed25519'
            generated = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                                       capture_output=True, timeout=10)
            self.assertEqual(generated.returncode, 0, generated.stderr.decode())
            self.assertEqual(generated.stdout + generated.stderr, b'')
            replacements, lines = [], []
            for line in source['content'].split('\n'):
                if line.startswith('HostKey '):
                    replacements.append({'original': line, 'delivered': 'HostKey ' + str(key)})
                    line = 'HostKey ' + str(key)
                lines.append(line)
            self.assertEqual(len(replacements), 2)
            config = Path(directory) / 'sshd_config'
            config.write_text('\n'.join(lines)); config.chmod(0o600)
            command = [*candidate['check_argv'][:-1], str(config)]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout + result.stderr, b'')
            public = key.with_suffix('.pub').read_text().split()[:2]
            record = {'candidate': candidate, 'command': command, 'actual_child_wait_exit': result.returncode,
                      'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(),
                      'hostkey_path_delivery_substitutions': replacements,
                      'check_config_path_delivery': {'original': candidate['check_argv'][-1], 'delivered': str(config)},
                      'delivered_config_content': config.read_text(),
                      'delivered_config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
                      'ephemeral_public_key': ' '.join(public), 'private_material_retained_or_adopted': False,
                      'keygen_actual_child_wait_exit': generated.returncode,
                      'daemon_or_listener_or_authentication_executed': False, 'native_azure_policy_proven': False}
        self.assertFalse(Path(directory).exists())
        self.record = {**record, 'owned_key_directory_removed': True}

    def test_native_child_no_new_privileges_survives_exec_and_cannot_be_unset(self):
        code = '''import ctypes,errno,json,os,subprocess,sys
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4
libc.prctl.restype=ctypes.c_int
before=libc.prctl(39,0,0,0,0)
assert before in (0,1)
assert libc.prctl(38,1,0,0,0)==0
assert libc.prctl(39,0,0,0,0)==1
query="import ctypes,errno,json; l=ctypes.CDLL(None,use_errno=True); l.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4; l.prctl.restype=ctypes.c_int; before=l.prctl(39,0,0,0,0); ctypes.set_errno(0); result=l.prctl(38,0,0,0,0); error=ctypes.get_errno(); after=l.prctl(39,0,0,0,0); assert before==after==1 and result==-1 and error==errno.EINVAL; print(json.dumps(dict(before=before,after=after,unset_result=result,unset_errno=error)))"
child=subprocess.run([sys.executable,'-I','-c',query],capture_output=True,timeout=5)
assert child.returncode==0 and child.stderr==b''
print(json.dumps(dict(before=before,after=1,exec_child=json.loads(child.stdout),exec_wait=child.returncode,uid=os.getuid())))
'''
        command = [sys.executable, '-I', '-c', code]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        observed = json.loads(result.stdout)
        self.assertEqual(observed['after'], 1)
        self.assertEqual(observed['exec_child']['before'], 1)
        self.assertEqual(observed['exec_child']['after'], 1)
        self.assertEqual(observed['exec_wait'], 0)
        self.record = {'scope': 'Ordinary owned Linux child PR_SET/GET_NO_NEW_PRIVS+exec primitive ONLY',
                       'source': code, 'actual_child_wait_exit': result.returncode, 'stdout': result.stdout.decode(),
                       'stderr': result.stderr.decode(), 'observed': observed, 'unit_enforcement_proven': False,
                       'setid_or_capability_escalation_attempted': False, 'pam_or_sshd_executed': False}


if __name__ == '__main__': unittest.main()

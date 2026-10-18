"""Local sshd -G parsing of private configurations without keys or listeners."""

import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_deployment_policy as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_ssh_preflight', ROOT/'Bootstrap/ssh_preflight.py')
SSH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SSH)
CAPTURES = []


class SSHPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.value = fixture.manifest()
        self.manifest = self.root/'manifest.json'
        self.write_manifest()
        self.pin = hashlib.sha256(Path(SSH.PARSER).read_bytes()).hexdigest()

    def write_manifest(self):
        self.manifest.write_bytes(fixture.encoded(self.value)); self.manifest.chmod(0o600)

    def audit(self):
        return SSH.audit(self.root, '/manifest.json', self.pin)

    def candidate(self):
        return SSH.PREFLIGHT.preflight(self.root, '/manifest.json', kind='deployment', include_candidate=True)

    def test_dual_family_cli_matches_all_explicit_settings_without_input_writes(self):
        before = self.manifest.read_bytes()
        args = [sys.executable, '-I', '-B', str(ROOT/'Bootstrap/ssh_preflight.py'), '--root', str(self.root),
                '--manifest', '/manifest.json', '--parser-sha256', self.pin]
        child = subprocess.run(args, capture_output=True, timeout=20)
        self.assertEqual((child.returncode, child.stderr), (0, b''), child.stderr)
        result = json.loads(child.stdout)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(result['matched_directives'].keys(), {key.lower() for key in SSH.SAFE_DIRECTIVES})
        self.assertEqual(len(result['matched_directives']['listenaddress']), 2)
        self.assertEqual(result['matched_directives']['allowusers'], [SSH.POLICY.ADMIN + '@' + self.value['admin'][key]['prefix']
                                                                   for key in ('ipv4', 'ipv6')])
        self.assertEqual([row['actual_returncode'] for row in result['parser']['commands']], [0, 0])
        self.assertEqual(result['parser']['commands'][-1]['arguments'], ['-G', '-e', '-f', '/dev/stdin'])
        self.assertEqual(self.manifest.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.manifest])
        CAPTURES.append(result)
        failed = subprocess.run([*args[:-1], '0'*64], capture_output=True, timeout=20)
        self.assertEqual((failed.returncode, failed.stdout, failed.stderr),
                         (75, b'', b'Private SSH configuration check refused\n'))
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_null_admin_ipv6_keeps_public_ipv6_separate_and_mismatches_refuse(self):
        self.value['admin']['ipv6'] = None
        self.value['public']['ipv6'] = fixture.net_fixture.PUBLIC6
        self.write_manifest(); result = self.audit()
        self.assertEqual(result['matched_directives']['listenaddress'], [self.value['admin']['ipv4']['address'] + ':22'])
        self.assertNotIn(self.value['public']['ipv6'], result['native_output']['content'])
        raw = result['native_output']['content'].encode('ascii'); expected = result['matched_directives']
        faults = [raw.replace(b'passwordauthentication no\n', b'passwordauthentication yes\n'),
                  raw.replace(b'permitrootlogin no\n', b''),
                  raw.replace(b'rekeylimit 268435456 3600\n', b'rekeylimit 268435456 7200\n'),
                  raw + b'passwordauthentication no\n', raw + b'allowusers unexpected\n',
                  raw + b'listenaddress [::]:22\n', raw + b'bareline\n', raw + b'key control\x01\n', raw[:-1]]
        for index, damaged in enumerate(faults):
            with self.subTest(index=index), self.assertRaises(ValueError): SSH.reconcile(damaged, expected)
        CAPTURES.append(result)

    def test_faulty_producer_or_unsafe_syntax_refuses_before_any_native_call(self):
        original = self.candidate()
        for injection in ('Include /etc/ssh/sshd_config\n', 'Match all\n', ' PermitRootLogin yes\n',
                          'PasswordAuthentication yes\n', 'UnknownDirective yes\n'):
            broken = copy.deepcopy(original)
            for row in (broken['candidate']['files'][0], broken['candidate']['ssh_policy']['files'][0]):
                row['content'] += injection
                raw = row['content'].encode('ascii'); row['bytes'] = len(raw); row['sha256'] = hashlib.sha256(raw).hexdigest()
            with self.subTest(injection=injection), patch.object(SSH.PREFLIGHT, 'preflight', return_value=broken), \
                    patch.object(SSH.NATIVE, 'PinnedExecutable', side_effect=AssertionError('early native')) as native:
                with self.assertRaisesRegex(ValueError, 'complete current SSH'): self.audit()
                native.assert_not_called()
        # Even a changed maintained producer cannot silently introduce an
        # include/match/continuation grammar into this developer-native bridge.
        for suffix in ('Include /etc/ssh/sshd_config\n', 'Match all\n', 'HostKey /tmp/other\\\n'):
            candidate = copy.deepcopy(original['candidate'])
            policy = candidate['ssh_policy']; row = policy['files'][0]
            row['content'] += suffix; raw = row['content'].encode('ascii')
            row['bytes'] = len(raw); row['sha256'] = hashlib.sha256(raw).hexdigest()
            candidate['files'][0] = copy.deepcopy(row)
            with self.subTest(suffix=suffix), patch.object(SSH.POLICY, 'bundle', return_value=policy):
                with self.assertRaisesRegex(ValueError, 'unsupported SSH'): SSH.parser_input(candidate)
        self.assertEqual(list(self.root.iterdir()), [self.manifest])

    def test_native_unsupported_algorithm_is_an_actual_parser_failure(self):
        raw, _ = SSH.parser_input(self.candidate()['candidate'])
        damaged = raw.replace(b'KexAlgorithms sntrup761x25519-sha512@openssh.com\n',
                              b'KexAlgorithms definitely-not-an-ssh-algorithm\n')
        self.assertNotEqual(raw, damaged)
        before = self.manifest.read_bytes()
        with contextlib.ExitStack() as stack:
            native = SSH.NATIVE.PinnedExecutable(stack, self.pin, path=SSH.PARSER, label='sshd',
                                                environment=SSH.ENVIRONMENT, timeout=10)
            with self.assertRaisesRegex(ValueError, 'sshd check refused'):
                native.run(['-G', '-e', '-f', '/dev/stdin'], damaged)
            self.assertNotEqual(native.commands[-1]['actual_returncode'], 0)
            self.assertIn(b'Bad SSH2 KexAlgorithms', native.last_stderr)
            self.assertEqual(native.last_stdout, b'')
            CAPTURES.append({'scope': 'EXPECTED NATIVE PARSER REFUSAL', 'commands': native.commands,
                             'stderr': native.last_stderr.decode('ascii')})
        self.assertEqual(self.manifest.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [self.manifest])

    def test_changed_original_manifest_refuses_after_native_and_environment_is_fixed(self):
        original = SSH.NATIVE.PinnedExecutable.run; calls = []
        def observed(native, arguments, *args, **kwargs):
            self.assertEqual(native.environment, SSH.ENVIRONMENT)
            self.assertNotIn('LD_PRELOAD', native.environment)
            result = original(native, arguments, *args, **kwargs); calls.append(arguments)
            if '-G' in arguments:
                self.value['dns_nodes']['controller'] = 'other-controller'; self.write_manifest()
            return result
        with patch.object(SSH.NATIVE.PinnedExecutable, 'run', observed):
            with self.assertRaisesRegex(ValueError, 'plan changed'): self.audit()
        self.assertEqual(calls, [['-V'], ['-G', '-e', '-f', '/dev/stdin']])
        self.assertEqual(list(self.root.iterdir()), [self.manifest])

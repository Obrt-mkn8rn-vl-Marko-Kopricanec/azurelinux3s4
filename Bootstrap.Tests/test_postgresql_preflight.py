"""Private PostgreSQL -C observations; no initialized cluster or server."""

import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_deployment_policy as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_pg_preflight', ROOT/'Bootstrap/postgresql_preflight.py')
PG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PG)
CAPTURES = []


class PostgreSQLPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.base.chmod(0o700)
        self.root = self.base/'source'; self.root.mkdir(mode=0o700)
        self.work = self.base/'scratch'; self.work.mkdir(mode=0o700)
        self.value = fixture.manifest()
        self.manifest = self.root/'manifest.json'; self.write_manifest()
        self.pin = hashlib.sha256(Path(PG.PARSER).read_bytes()).hexdigest()

    def write_manifest(self):
        self.manifest.write_bytes(fixture.encoded(self.value)); self.manifest.chmod(0o600)

    def audit(self):
        return PG.audit(self.root, '/manifest.json', self.work, self.pin)

    def candidate(self):
        return PG.PREFLIGHT.preflight(self.root, '/manifest.json', kind='deployment', include_candidate=True)

    def test_cli_matches_all_seven_native_values_and_removes_only_private_scratch(self):
        original = self.manifest.read_bytes()
        args = [sys.executable, '-I', '-B', str(ROOT/'Bootstrap/postgresql_preflight.py'), '--root', str(self.root),
                '--manifest', '/manifest.json', '--work-parent', str(self.work), '--parser-sha256', self.pin]
        child = subprocess.run(args, capture_output=True, timeout=20)
        self.assertEqual((child.returncode, child.stderr), (0, b''), child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result['settings'], {'listen_addresses': '127.0.0.1,::1', 'port': '5432',
            'password_encryption': 'scram-sha-256', 'unix_socket_directories': '/run/postgresql',
            'fsync': 'on', 'full_page_writes': 'on', 'synchronous_commit': 'on'})
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertFalse(result['hba_commitment_only']['native_hba_parsing_performed'])
        self.assertEqual(set(result['fixture']), {'postgresql.conf', 'postgresql.auto.conf'})
        self.assertEqual(result['fixture']['postgresql.auto.conf']['bytes'], 0)
        self.assertEqual(result['fixture']['postgresql.conf']['sha256'], result['configuration']['sha256'])
        commands = result['parser']['commands']
        self.assertEqual([row['actual_returncode'] for row in commands], [0]*8)
        self.assertEqual([row['arguments'][-1] for row in commands[1:]], list(PG.SETTINGS))
        for command in commands[1:]:
            self.assertEqual(command['arguments'][::2], ['-D', '-C'])
            self.assertTrue(Path(command['arguments'][1]).is_relative_to(self.work))
            self.assertEqual(command['stderr_bytes'], 0)
        self.assertEqual(self.manifest.read_bytes(), original)
        self.assertEqual(list(self.root.iterdir()), [self.manifest]); self.assertEqual(list(self.work.iterdir()), [])
        CAPTURES.append(result)
        refused = subprocess.run([*args[:-1], '0'*64], capture_output=True, timeout=20)
        self.assertEqual((refused.returncode, refused.stdout, refused.stderr),
                         (75, b'', b'Private PostgreSQL configuration check refused\n'))
        self.assertEqual(list(self.work.iterdir()), [])

    def test_faulty_producer_cannot_add_includes_preload_runtime_query_or_unbound_bytes(self):
        original = self.candidate()
        for suffix in ("include '/etc/postgresql.conf'\n", "shared_preload_libraries = 'foreign'\n",
                       "shared_memory_size = 1\n", 'fsync = off\n'):
            broken = copy.deepcopy(original); row = broken['candidate']['files'][2]
            self.assertEqual(row['file'], 'postgresql/listener.conf')
            row['content'] += suffix; raw = row['content'].encode('ascii')
            row['bytes'] = len(raw); row['sha256'] = hashlib.sha256(raw).hexdigest()
            with self.subTest(suffix=suffix), patch.object(PG.PREFLIGHT, 'preflight', return_value=broken), \
                    patch.object(PG.NATIVE, 'PinnedExecutable', side_effect=AssertionError('early native')) as native:
                with self.assertRaisesRegex(ValueError, 'complete current PostgreSQL'): self.audit()
                native.assert_not_called()
            self.assertEqual(list(self.work.iterdir()), [])
        broken = copy.deepcopy(original); broken['candidate']['files'][2]['sha256'] = '0'*64
        with patch.object(PG.PREFLIGHT, 'preflight', return_value=broken), \
                patch.object(PG.NATIVE, 'PinnedExecutable', side_effect=AssertionError('early native')):
            with self.assertRaises(ValueError): self.audit()
        with self.assertRaisesRegex(ValueError, 'outside'):
            PG.audit(self.root, '/manifest.json', self.root, self.pin)

    def test_invalid_boolean_gives_actual_native_error_without_cluster_creation(self):
        raw, _, _ = PG.parser_input(self.candidate()['candidate'])
        damaged = raw.replace(b'fsync = on\n', b'fsync = invalid-boolean\n')
        self.assertNotEqual(raw, damaged)
        with tempfile.TemporaryDirectory(dir=self.work) as temporary, contextlib.ExitStack() as stack:
            directory = PG.RELEASE.anchor(stack, temporary, [])
            PG.create_fixture(directory, damaged); before = PG.fixture_observation(directory)
            native = PG.NATIVE.PinnedExecutable(stack, self.pin, path=PG.PARSER, label='postgres',
                                               environment=PG.ENVIRONMENT, timeout=10)
            with self.assertRaisesRegex(ValueError, 'postgres check refused'):
                native.run(['-D', temporary, '-C', 'fsync'])
            self.assertNotEqual(native.commands[-1]['actual_returncode'], 0)
            self.assertIn(b'parameter "fsync" requires a Boolean value', native.last_stderr)
            self.assertEqual(native.last_stdout, b'')
            self.assertEqual(PG.fixture_observation(directory), before)
            self.assertEqual(set(os.listdir(directory)), {'postgresql.conf', 'postgresql.auto.conf'})
            CAPTURES.append({'scope': 'EXPECTED NATIVE CONFIGURATION REFUSAL', 'commands': native.commands,
                             'stderr': native.last_stderr.decode('ascii')})
        self.assertEqual(list(self.work.iterdir()), [])

    def test_native_value_mismatch_and_late_original_source_drift_withhold_success(self):
        original = PG.NATIVE.PinnedExecutable.run
        for fault in ('native-value', 'source'):
            calls = []
            def observed(native, arguments, *args, **kwargs):
                self.assertEqual(native.environment, PG.ENVIRONMENT)
                result = original(native, arguments, *args, **kwargs); calls.append(arguments)
                if arguments[-1] == 'synchronous_commit':
                    if fault == 'native-value': return b'off\n'
                    self.value['dns_nodes']['controller'] = 'changed-controller'; self.write_manifest()
                return result
            message = 'setting differs' if fault == 'native-value' else 'plan changed'
            with self.subTest(fault=fault), patch.object(PG.NATIVE.PinnedExecutable, 'run', observed):
                with self.assertRaisesRegex(ValueError, message): self.audit()
            self.assertEqual(len(calls), 8)
            self.assertEqual(list(self.work.iterdir()), [])

    def test_auto_configuration_tamper_refuses_before_next_native_query(self):
        original = PG.NATIVE.PinnedExecutable.run; calls = []
        def observed(native, arguments, *args, **kwargs):
            result = original(native, arguments, *args, **kwargs); calls.append(arguments)
            if '-C' in arguments:
                automatic = Path(arguments[1])/'postgresql.auto.conf'
                automatic.chmod(0o600); automatic.write_bytes(b'fsync = off\n'); automatic.chmod(0o400)
            return result
        with patch.object(PG.NATIVE.PinnedExecutable, 'run', observed):
            with self.assertRaisesRegex(ValueError, 'owner-only PostgreSQL'): self.audit()
        self.assertEqual(len(calls), 2)
        self.assertEqual(list(self.work.iterdir()), [])

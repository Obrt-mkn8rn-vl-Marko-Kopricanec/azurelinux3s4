"""Complete private-root preflight and capability refusals; no host invocation."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_preflight', ROOT / 'Bootstrap/preflight.py')
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)


class PrivatePreflightTests(fixture.ReleaseFixture):
    def test_complete_application_plan_is_read_only_and_keeps_every_authority_false(self):
        before = self.snapshot()
        result = PREFLIGHT.preflight(self.root, '/manifest.json', include_candidate=True)
        self.assertEqual(result['kind'], 'applications')
        self.assertEqual(len(result['files']), 14)
        self.assertEqual(len(result['candidate']['files']), 9)
        self.assertEqual(len(result['publication']['service_account_policy']['accounts']), 6)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertTrue(all(value is False for value in result['candidate']['authority'].values()))
        self.assertEqual(result['manifest_sha256'], hashlib.sha256(self.manifest_file.read_bytes()).hexdigest())
        self.assertEqual(result['software_sha256']['azurelinux3s4.sh'], hashlib.sha256((ROOT / 'azurelinux3s4.sh').read_bytes()).hexdigest())
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'var').exists())
        self.assertFalse((self.root / 'usr').exists())
        raw = json.dumps(result)
        self.assertNotIn('finite-model-only-password', raw)
        self.assertNotIn('finite opaque Email input', raw)
        self.assertNotIn('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=', raw)

    def test_deployment_cli_emits_candidate_only_when_requested_and_never_writes(self):
        before = self.snapshot()
        command = [sys.executable, '-B', str(ROOT / 'Bootstrap/preflight.py'), '--root', str(self.root),
                   '--manifest', '/manifest.json', '--kind', 'deployment']
        child = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(len(result['files']), 8)
        self.assertNotIn('candidate', result)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(self.snapshot(), before)
        bad = subprocess.run([*command[:-2], '--kind', 'applications', '--manifest', '/../../etc/passwd'],
                             capture_output=True, timeout=10)
        self.assertEqual((bad.returncode, bad.stdout, bad.stderr), (75, b'', b'Private development preflight refused\n'))
        self.assertEqual(self.snapshot(), before)

    def test_adapter_rejects_writes_absolute_paths_foreign_descriptors_and_links(self):
        fd = os.open(self.root, PREFLIGHT.READ | os.O_DIRECTORY)
        bridge = PREFLIGHT.ReadOnlyRoot(fd)
        try:
            root = bridge.open('/', PREFLIGHT.READ | os.O_DIRECTORY)
            for flags in (PREFLIGHT.READ | os.O_CREAT, PREFLIGHT.READ | os.O_WRONLY,
                          PREFLIGHT.READ | os.O_TRUNC, os.O_RDONLY):
                with self.subTest(flags=flags):
                    with self.assertRaises(ValueError):
                        bridge.open('manifest.json', flags, dir_fd=root)
            for path in ('../outside', '/etc/passwd', '..'):
                with self.subTest(path=path):
                    with self.assertRaises(ValueError):
                        bridge.open(path, PREFLIGHT.READ, dir_fd=root)
            with self.assertRaises(ValueError):
                bridge.open('manifest.json', PREFLIGHT.READ, dir_fd=fd)
            (self.root / 'link').symlink_to(self.manifest_file)
            with self.assertRaises(OSError):
                bridge.open('link', PREFLIGHT.READ, dir_fd=root)
            with self.assertRaises(AttributeError):
                bridge.write(0, b'not permitted')
            bridge.close(root)
            bridge.finish()
            self.assertEqual(bridge.live, set())
        finally:
            os.close(fd)

    def test_unprotected_root_late_credential_failure_and_linked_inputs_refuse(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, '0700'):
            PREFLIGHT.preflight(self.root, '/manifest.json')
        self.root.chmod(0o700)
        database = self.root / 'etc/mk8.dns/controller/database.txt'
        original = database.read_bytes()
        database.write_bytes(b'Host=unsupported;Password=must-not-be-serialized')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            PREFLIGHT.preflight(self.root, '/manifest.json')
        self.assertEqual(self.snapshot(), before)
        database.write_bytes(original)
        alias = self.root / 'database-alias'; os.link(database, alias)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'single-link'):
            PREFLIGHT.preflight(self.root, '/manifest.json')
        self.assertEqual(self.snapshot(), before)

    def test_assembly_drift_and_native_or_publication_capabilities_fail_closed(self):
        original = PREFLIGHT.module
        def changed(name):
            result = original(name)
            if name == 'pack':
                artifacts = result.artifacts()
                artifacts['azurelinux3s4.sh'] += b'# drift\n'
                result.artifacts = lambda: artifacts
            return result
        with patch.object(PREFLIGHT, 'module', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'differs'):
                PREFLIGHT.preflight(self.root, '/manifest.json')
        with self.assertRaisesRegex(ValueError, 'cannot invoke'):
            PREFLIGHT.denied()
        for operation in ('CDLL', 'flock'):
            with self.assertRaisesRegex(ValueError, 'native publication'):
                getattr(PREFLIGHT.NoNativeOperations(), operation)

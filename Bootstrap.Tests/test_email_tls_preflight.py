"""Whole private plans plus local synthetic TLS, with no application or listener."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

import test_deployment_releases as fixture
import test_tls_inputs as materials


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_email_tls', ROOT/'Bootstrap/email_tls_preflight.py')
EMAIL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EMAIL)


class EmailTlsPreflightTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        materials.TlsInputTests.setUpClass()
        cls.addClassCleanup(materials.TlsInputTests.doClassCleanups)
        cls.materials = materials.TlsInputTests.originals
        cls.pin = materials.TlsInputTests.pin

    def setUp(self):
        super().setUp()
        self.value['domains']['mk8.email'] = 'mail.example.test'
        for role in ('worker', 'gateway'):
            path = self.root/'etc/mk8.email'/(role + '.json')
            value = json.loads(path.read_bytes())
            value['Smtp']['Hostname'] = self.value['domains']['mk8.email']
            self.configuration(role, value)
        for source, target in (('leaf.pem', 'tls-certificate.pem'), ('leaf.key', 'tls-key.pem')):
            (self.root/'etc/mk8.email/gateway'/target).write_bytes(self.materials[source])
        self.anchors = self.root/'trust.pem'
        self.anchors.write_bytes(self.materials['ca.pem']); self.anchors.chmod(0o600)

    def configuration(self, role, value):
        raw = fixture.encoded(value); path = self.root/'etc/mk8.email'/(role + '.json')
        path.write_bytes(raw)
        self.documents['mk8.email']['configuration'][role + '.json'] = hashlib.sha256(raw).hexdigest()
        self.seal('mk8.email'); self.manifest_file.write_bytes(fixture.encoded(self.value))

    def arguments(self):
        return dict(private_root=self.root, manifest='/manifest.json', anchors=self.anchors,
                    openssl_sha256=self.pin, at=int(time.time()), minimum_seconds=3600)

    def test_whole_shipped_plan_binds_exact_configured_tls_sources_and_cli_without_writes(self):
        before = self.snapshot()
        result = EMAIL.audit(**self.arguments())
        self.assertEqual(result['domain'], self.value['domains']['mk8.email'])
        self.assertEqual([row['role'] for row in result['roles']], ['gateway'])
        checked = result['roles'][0]['tls']
        self.assertTrue(checked['source_commitments_supplied'])
        self.assertTrue(all(checked['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(checked['sources']['certificate']['sha256'], hashlib.sha256(self.materials['leaf.pem']).hexdigest())
        self.assertEqual(result['software_sha256']['azurelinux3s4.sh'], hashlib.sha256((ROOT/'azurelinux3s4.sh').read_bytes()).hexdigest())
        self.assertEqual(len(result['files']), 14)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root/'var').exists())
        args = self.arguments(); args['root'] = args.pop('private_root')
        command = [sys.executable, '-I', '-B', str(ROOT/'Bootstrap/email_tls_preflight.py')]
        command.extend(item for name,value in args.items() for item in ('--' + name.replace('_', '-'), str(value)))
        child = subprocess.run(command, capture_output=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)['publication_sha256'], result['publication_sha256'])
        self.assertNotIn(b'PRIVATE KEY', child.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_optional_worker_pair_is_also_checked_and_never_bypasses_late_gateway(self):
        path = self.root/'etc/mk8.email/worker.json'; value = json.loads(path.read_bytes())
        value['Tls'] = {'CertificatePath': '/run/credentials/mk8-email-worker.service/tls-certificate.pem',
                        'CertificateKeyPath': '/run/credentials/mk8-email-worker.service/tls-key.pem'}
        for source,target in (('leaf.pem', 'tls-certificate.pem'), ('leaf.key', 'tls-key.pem')):
            path = self.root/'etc/mk8.email/worker'/target
            path.write_bytes(self.materials[source]); path.chmod(0o600)
        self.configuration('worker', value)
        before = self.snapshot(); result = EMAIL.audit(**self.arguments())
        self.assertEqual([row['role'] for row in result['roles']], ['worker', 'gateway'])
        self.assertTrue(all(row['tls']['source_commitments_supplied'] for row in result['roles']))
        self.assertEqual(self.snapshot(), before)
        gateway = self.root/'etc/mk8.email/gateway/tls-key.pem'
        gateway.write_bytes(self.materials['other.key']); before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'public components differ'): EMAIL.audit(**self.arguments())
        self.assertEqual(self.snapshot(), before)

    def test_faulty_credential_commitments_paths_or_missing_pairs_refuse_before_native_calls(self):
        candidate = EMAIL.PREFLIGHT.preflight(self.root, '/manifest.json', include_candidate=True)
        for problem in ('commitment', 'path', 'missing', 'manifest'):
            bad = copy.deepcopy(candidate)
            gateway = bad['candidate']['email_credentials'][1]
            row = next(row for row in gateway['inputs'] if row['id'] == 'tls-key.pem')
            if problem == 'commitment': row['sha256'] = '0' * 64
            if problem == 'path': row['source'] = '/etc/foreign/tls-key.pem'
            if problem == 'missing': gateway['inputs'].remove(row)
            if problem == 'manifest': bad['manifest_sha256'] = '0' * 64
            before = self.snapshot()
            with self.subTest(problem=problem), patch.object(EMAIL.PREFLIGHT, 'preflight', return_value=bad), \
                    patch.object(EMAIL.TLS, 'NativeOpenSSL', side_effect=AssertionError('unbound native execution')) as native:
                with self.assertRaises(ValueError): EMAIL.audit(**self.arguments())
                native.assert_not_called()
            self.assertEqual(self.snapshot(), before)

    def test_post_crypto_original_credential_or_trust_change_prevents_receipt(self):
        original = EMAIL.TLS.audit
        for path, message in ((self.root/'etc/mk8.email/worker/messaging-key.txt', 'application plan changed'),
                              (self.anchors, 'changed since admission')):
            raw = path.read_bytes()
            def changed(*args, **kwargs):
                result = original(*args, **kwargs)
                path.write_bytes(raw + b'\n')
                return result
            with self.subTest(path=path.name), patch.object(EMAIL.TLS, 'audit', side_effect=changed):
                with self.assertRaisesRegex(ValueError, message): EMAIL.audit(**self.arguments())
            path.write_bytes(raw)
            self.assertFalse((self.root/'var').exists())

    def test_early_full_plan_failure_and_wrong_key_cli_withhold_all_json(self):
        path = self.root/'etc/mk8.dns/controller/database.txt'
        original = path.read_bytes(); path.write_bytes(b'invalid original DSN')
        with patch.object(EMAIL.TLS, 'audit', side_effect=AssertionError('early native call')) as native:
            with self.assertRaises(ValueError): EMAIL.audit(**self.arguments())
            native.assert_not_called()
        path.write_bytes(original)
        (self.root/'etc/mk8.email/gateway/tls-key.pem').write_bytes(self.materials['other.key'])
        before = self.snapshot()
        child = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'Bootstrap/email_tls_preflight.py'),
                                '--root', str(self.root), '--manifest', '/manifest.json',
                                '--anchors', str(self.anchors), '--openssl-sha256', self.pin],
                               capture_output=True, timeout=20)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (75, b'', b'Private Email TLS preflight refused\n'))
        self.assertEqual(self.snapshot(), before)

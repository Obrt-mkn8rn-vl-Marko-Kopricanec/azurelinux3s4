"""Private synthetic TLS materials; no server, trust installation or network IO."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('development_tls_inputs', ROOT / 'Bootstrap/tls_inputs.py')
TLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TLS)


class TlsInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(dir=Path.home() / '.cache')
        cls.addClassCleanup(cls.material.cleanup)
        folder = Path(cls.material.name)
        folder.chmod(0o700)
        cls.pin = hashlib.sha256(Path(TLS.OPENSSL).read_bytes()).hexdigest()
        def openssl(*args):
            child = subprocess.run([TLS.OPENSSL, *args], cwd=folder, env=TLS.ENVIRONMENT,
                                   capture_output=True, timeout=10, check=False)
            if child.returncode:
                raise AssertionError('Private synthetic TLS setup failed: ' + child.stderr.decode('ascii', 'replace'))
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                '-days', '365', '-sha256', '-subj', '/CN=Development Test CA',
                '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-addext', 'subjectKeyIdentifier=hash', '-keyout', 'ca.key', '-out', 'ca.pem')
        openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=ignored.example.test')
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'other.key')
        for index, (name, purpose, san) in enumerate((
            ('leaf', 'serverAuth', 'DNS:mail.example.test,DNS:gateway.example.test'),
            ('client', 'clientAuth', 'DNS:mail.example.test'),
            ('cn-only', 'serverAuth', None),
            ('wildcard', 'serverAuth', 'DNS:*.example.test'),
        ), 2):
            config = ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                      'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=' + purpose + '\n')
            if san is not None: config += 'subjectAltName=' + san + '\n'
            (folder / 'leaf.ext').write_text(config)
            openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                    '-set_serial', str(index), '-days', '2', '-sha256', '-extfile', 'leaf.ext', '-out', name + '.pem')
        openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                '-keyout', 'intermediate.key', '-out', 'intermediate.csr', '-subj', '/CN=Development Intermediate CA')
        (folder/'intermediate.ext').write_text('basicConstraints=critical,CA:TRUE,pathlen:0\n'
                                              'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n'
                                              'authorityKeyIdentifier=keyid,issuer\n')
        openssl('x509', '-req', '-in', 'intermediate.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                '-set_serial', '10', '-days', '3', '-sha256', '-extfile', 'intermediate.ext', '-out', 'intermediate.pem')
        (folder/'leaf.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                                      'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'
                                      'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:mail.example.test\n')
        openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'intermediate.pem', '-CAkey', 'intermediate.key',
                '-set_serial', '11', '-days', '2', '-sha256', '-extfile', 'leaf.ext', '-out', 'chained.pem')
        cls.originals = {name: (folder / name).read_bytes() for name in
                         ('leaf.pem', 'leaf.key', 'ca.pem', 'other.key', 'client.pem', 'cn-only.pem', 'wildcard.pem',
                          'intermediate.pem', 'chained.pem')}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home() / '.cache')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        for name, raw in self.originals.items():
            path = self.root / name; path.write_bytes(raw); path.chmod(0o600)

    def arguments(self):
        return dict(domain='mail.example.test', certificate=self.root/'leaf.pem', key=self.root/'leaf.key',
                    anchors=self.root/'ca.pem', openssl_sha256=self.pin, at=int(time.time()), minimum_seconds=3600)

    def snapshot(self):
        return {path.name: (path.read_bytes(), TLS.RELEASE.identity(path.stat())) for path in self.root.iterdir()
                if path.is_file() and not path.is_symlink()}

    def test_real_private_crypto_and_cli_bind_all_inputs_without_secret_output_or_writes(self):
        before = self.snapshot()
        args = self.arguments()
        result = TLS.audit(**args)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(result['dns_subject_alternative_names'], ['mail.example.test', 'gateway.example.test'])
        self.assertEqual(result['anchor_certificates'], 1)
        self.assertEqual(result['intermediate_certificates'], 0)
        self.assertEqual(len(result['openssl']['commands']), 7)
        self.assertTrue(all(row['actual_returncode'] == 0 for row in result['openssl']['commands']))
        command = [sys.executable, '-I', '-B', str(ROOT/'Bootstrap/tls_inputs.py')]
        for name, value in args.items():
            command.extend(('--' + name.replace('_', '-'), str(value)))
        child = subprocess.run(command, capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)
        receipt = json.loads(child.stdout)
        self.assertEqual(receipt['public_key_der_sha256'], result['public_key_der_sha256'])
        self.assertEqual(receipt['sources'], result['sources'])
        self.assertNotIn(b'PRIVATE KEY', child.stdout)
        self.assertNotIn(self.originals['leaf.key'].splitlines()[1], child.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_explicit_intermediate_chain_and_both_validity_instants_are_required(self):
        before = self.snapshot()
        args = self.arguments(); args['certificate'] = self.root/'chained.pem'
        with self.assertRaisesRegex(ValueError, 'OpenSSL check refused'): TLS.audit(**args)
        args['intermediates'] = self.root/'intermediate.pem'
        result = TLS.audit(**args)
        self.assertEqual(result['intermediate_certificates'], 1)
        self.assertEqual(result['sources']['intermediates']['sha256'],
                         hashlib.sha256(self.originals['intermediate.pem']).hexdigest())
        checks = [row['arguments'] for row in result['openssl']['commands'] if row['arguments'][0] == 'verify']
        self.assertEqual([row[-1] for row in checks], [str(args['at']), str(args['at'] + args['minimum_seconds'])])
        self.assertTrue(all('-untrusted' in row for row in checks))
        args['minimum_seconds'] = 10 * 86400
        with self.assertRaisesRegex(ValueError, 'OpenSSL check refused'): TLS.audit(**args)
        self.assertEqual(self.snapshot(), before)

    def test_wrong_key_hostname_trust_purpose_and_future_expiry_refuse_without_input_changes(self):
        before = self.snapshot()
        for change in ({'key': self.root/'other.key'}, {'domain': 'wrong.example.test'},
                       {'anchors': self.root/'leaf.pem'}, {'certificate': self.root/'client.pem'},
                       {'at': int(time.time()) + 10 * 86400}):
            with self.subTest(change={key: str(value) for key,value in change.items()}):
                args = self.arguments(); args.update(change)
                with self.assertRaises(ValueError): TLS.audit(**args)
                self.assertEqual(self.snapshot(), before)

    def test_noncanonical_cn_only_wildcard_pem_and_unprotected_sources_refuse(self):
        for filename in ('cn-only.pem', 'wildcard.pem'):
            args = self.arguments(); args['certificate'] = self.root/filename
            with self.assertRaisesRegex(ValueError, 'DNS subject alternative'): TLS.audit(**args)
        path = self.root/'leaf.pem'
        original = path.read_bytes()
        for raw in (original + b'extra\n', original + original,
                    b'-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n'):
            path.write_bytes(raw)
            with patch.object(TLS, 'NativeOpenSSL', side_effect=AssertionError('native execution forbidden')) as native:
                with self.assertRaises(ValueError): TLS.audit(**self.arguments())
                native.assert_not_called()
        path.write_bytes(original); path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, '0600'): TLS.audit(**self.arguments())
        path.chmod(0o600)
        alias = self.root/'alias'; os.link(path, alias)
        with self.assertRaisesRegex(ValueError, 'single-link'): TLS.audit(**self.arguments())
        alias.unlink(); path.unlink(); path.symlink_to(self.root/'ca.pem')
        with self.assertRaises((ValueError, OSError)): TLS.audit(**self.arguments())

    def test_binary_pin_source_change_and_native_timeout_never_return_success(self):
        args = self.arguments(); args['openssl_sha256'] = '0' * 64
        with patch.object(TLS.NativeOpenSSL, 'run', side_effect=AssertionError('unadmitted native execution')) as native:
            with self.assertRaisesRegex(ValueError, 'pin mismatch'): TLS.audit(**args)
            native.assert_not_called()
        original = TLS.NativeOpenSSL.run
        def changed(native, arguments, *args, **kwargs):
            result = original(native, arguments, *args, **kwargs)
            if arguments[0] == 'version':
                (self.root/'leaf.key').write_bytes(self.originals['leaf.key'] + b'\n')
            return result
        with patch.object(TLS.NativeOpenSSL, 'run', changed):
            with self.assertRaisesRegex(ValueError, 'changed since admission'): TLS.audit(**self.arguments())
        (self.root/'leaf.key').write_bytes(self.originals['leaf.key'])
        args = self.arguments()
        argv = [item for name,value in args.items() for item in ('--' + name.replace('_', '-'), str(value))]
        out, err = io.StringIO(), io.StringIO()
        with patch.object(TLS.subprocess, 'run', side_effect=subprocess.TimeoutExpired('owned-native-check', 10)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(TLS.main(argv), 75)
        self.assertEqual((out.getvalue(), err.getvalue()), ('', 'Local TLS input check refused\n'))

    def test_sealed_trust_bytes_and_fixed_native_environment_prevent_external_configuration(self):
        with contextlib.ExitStack() as stack:
            fd = TLS.sealed_input(stack, 'test', self.originals['ca.pem'])
            self.assertEqual(os.read(fd, len(self.originals['ca.pem']) + 1), self.originals['ca.pem'])
            with self.assertRaises(PermissionError): os.write(fd, b'foreign')
            native = TLS.NativeOpenSSL(stack, self.pin)
            response = subprocess.CompletedProcess([], 0, b'bounded result', b'')
            with patch.object(TLS.subprocess, 'run', return_value=response) as run:
                native.run(['pkey', '-pubout'], self.originals['leaf.key'], (fd,))
            args, kwargs = run.call_args
            self.assertEqual(args[0], [TLS.OPENSSL, 'pkey', '-pubout'])
            self.assertEqual(kwargs['input'], self.originals['leaf.key'])
            self.assertEqual(kwargs['env'], TLS.ENVIRONMENT)
            self.assertEqual(kwargs['env']['OPENSSL_CONF'], '/dev/null')
            self.assertNotIn('LD_PRELOAD', kwargs['env'])
            self.assertEqual(kwargs['pass_fds'], (native.fd, fd))
            self.assertEqual(kwargs['executable'], '/proc/self/fd/' + str(native.fd))
            self.assertEqual(kwargs['timeout'], 10)
            self.assertEqual(kwargs['cwd'], '/')

"""Real ephemeral Ed25519 signatures over complete synthetic release bindings."""

import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_release_attestation', ROOT/'Bootstrap/release_attestation.py')
ATTEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ATTEST)
CAPTURES = []


class ReleaseAttestationTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        cls.addClassCleanup(cls.material.cleanup)
        cls.keys = Path(cls.material.name); cls.keys.chmod(0o700)
        cls.openssl_pin = hashlib.sha256(Path(ATTEST.INPUTS.OPENSSL).read_bytes()).hexdigest()
        for label in ('signer', 'other'):
            cls.native('genpkey', '-algorithm', 'ED25519', '-out', str(cls.keys/(label+'.pem')))
            (cls.keys/(label+'.pem')).chmod(0o600)
            cls.native('pkey', '-in', str(cls.keys/(label+'.pem')), '-pubout', '-outform', 'DER',
                       '-out', str(cls.keys/(label+'.der')))

    @classmethod
    def native(cls, *arguments):
        child = subprocess.run([ATTEST.INPUTS.OPENSSL, *arguments], env=ATTEST.INPUTS.ENVIRONMENT,
                               capture_output=True, timeout=10)
        if child.returncode != 0:
            raise AssertionError('Ephemeral attestation fixture failed: ' + child.stderr.decode('ascii', 'replace'))

    def setUp(self):
        super().setUp()
        self.app = 'mk8.sava'; self.commit = '1'*40; self.tree = '2'*40
        self.release = self.root/'staged-release'
        roles = {role: self.folder(self.app)/role for role in self.n['REL_PROGRAMS'][self.app]}
        configurations = {name: self.root/'etc'/self.app/name for name in self.n['REL_CONFIGS'][self.app]}
        staged = ATTEST.RELEASE.stage(self.app, self.commit, self.tree, roles, configurations, self.release)
        self.manifest_sha = staged['declaration']['manifest_sha256']
        self.public = self.root/'signer.der'; self.public.write_bytes((self.keys/'signer.der').read_bytes()); self.public.chmod(0o600)
        self.key_sha = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.attestation = self.root/'attestation.json'; self.signature = self.root/'signature.ed25519'
        self.current = 1792335600
        self.value = {'schema': 1, 'purpose': 'azurelinux3s4-application-release', 'application': self.app,
                      'commit': self.commit, 'tree': self.tree, 'manifest_sha256': self.manifest_sha,
                      'key_sha256': self.key_sha, 'sequence': 12,
                      'not_before': self.current-60, 'not_after': self.current+3600}
        self.sign()

    def sign(self, domain=None):
        raw = (json.dumps(self.value, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')
        self.attestation.write_bytes(raw); self.attestation.chmod(0o600)
        message = self.root/'signing-message'; message.write_bytes((ATTEST.DOMAIN if domain is None else domain)+raw)
        message.chmod(0o600)
        self.native('pkeyutl', '-sign', '-rawin', '-inkey', str(self.keys/'signer.pem'),
                    '-in', str(message), '-out', str(self.signature))
        self.signature.chmod(0o600); message.unlink()

    def arguments(self):
        return dict(app=self.app, commit=self.commit, tree=self.tree, manifest_sha256=self.manifest_sha,
                    release=self.release, attestation=self.attestation, signature=self.signature,
                    public_key=self.public, public_key_sha256=self.key_sha, openssl_sha256=self.openssl_pin,
                    minimum_sequence=12, at=self.current)

    def test_cli_valid_signature_binds_every_payload_without_modifying_sources(self):
        before = self.snapshot()
        command = [sys.executable, '-I', '-B', str(ROOT/'Bootstrap/release_attestation.py')]
        for name, value in self.arguments().items(): command.extend(('--'+name.replace('_','-'), str(value)))
        child = subprocess.run(command, capture_output=True, timeout=20)
        self.assertEqual((child.returncode, child.stderr), (0, b''), child.stderr)
        result = json.loads(child.stdout)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(result['files'], 16)
        self.assertEqual(result['attestation'], self.value)
        self.assertEqual(result['signed_message_sha256'], hashlib.sha256(ATTEST.DOMAIN+self.attestation.read_bytes()).hexdigest())
        self.assertEqual([row['actual_returncode'] for row in result['openssl']['commands']], [0,0])
        self.assertEqual(result['sources']['public_key']['bytes'], 44)
        self.assertEqual(result['sources']['signature']['bytes'], 64)
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append({'result': result, 'public_key_hex': self.public.read_bytes().hex(),
                         'signature_hex': self.signature.read_bytes().hex(), 'attestation': self.attestation.read_text()})

    def test_wrong_signature_key_and_domain_fail_actual_native_verification(self):
        original_key = self.public.read_bytes(); original_sha = self.key_sha
        for fault in ('signature', 'key', 'domain'):
            self.public.write_bytes(original_key); self.key_sha = original_sha; self.value['key_sha256'] = self.key_sha; self.sign()
            if fault == 'signature':
                raw = bytearray(self.signature.read_bytes()); raw[0] ^= 1; self.signature.write_bytes(raw)
            elif fault == 'key':
                self.public.write_bytes((self.keys/'other.der').read_bytes()); self.key_sha = hashlib.sha256(self.public.read_bytes()).hexdigest()
                self.value['key_sha256'] = self.key_sha; self.sign()
            else: self.sign(domain=b'unrelated signing purpose\n')
            original = ATTEST.INPUTS.NativeOpenSSL.run; captured = []
            def observed(native, arguments, *args, **kwargs):
                try: return original(native, arguments, *args, **kwargs)
                finally:
                    if arguments[0] == 'pkeyutl': captured.append(list(native.commands))
            before = self.snapshot()
            with self.subTest(fault=fault), patch.object(ATTEST.INPUTS.NativeOpenSSL, 'run', observed):
                with self.assertRaisesRegex(ValueError, 'OpenSSL check refused'): ATTEST.audit(**self.arguments())
            self.assertEqual(len(captured), 1); self.assertNotEqual(captured[0][-1]['actual_returncode'], 0)
            self.assertEqual(self.snapshot(), before)
            CAPTURES.append({'scope': 'EXPECTED NATIVE SIGNATURE REFUSAL', 'fault': fault, 'commands': captured[0]})

    def test_scope_time_sequence_and_canonicality_refuse_before_native(self):
        changes = [('application', 'mk8.email'), ('commit', '9'*40), ('manifest_sha256', '0'*64),
                   ('key_sha256', '0'*64), ('sequence', 11), ('sequence', True), ('sequence', 2**63),
                   ('not_before', self.current+1), ('not_after', self.current),
                   ('not_after', self.current+ATTEST.MAX_VALIDITY+1), ('not_before', False), ('schema', True)]
        for name, value in changes:
            changed = dict(self.value); changed[name] = value
            raw = (json.dumps(changed,sort_keys=True,separators=(',',':'))+'\n').encode()
            with self.subTest(name=name,value=value), self.assertRaises(ValueError):
                ATTEST.envelope(raw,self.app,self.commit,self.tree,self.manifest_sha,self.key_sha,12,self.current)
        valid = self.attestation.read_bytes()
        malformed = (b'{"schema":1,'+valid[1:], valid[:-1], valid.replace(b'"schema":1', b'"schema":NaN'),
                     json.dumps(self.value,indent=2).encode()+b'\n')
        for raw in malformed:
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                ATTEST.envelope(raw,self.app,self.commit,self.tree,self.manifest_sha,self.key_sha,12,self.current)
        self.value['not_after'] = self.current; self.sign()
        with patch.object(ATTEST.INPUTS, 'NativeOpenSSL', side_effect=AssertionError('early native')) as native:
            with self.assertRaisesRegex(ValueError,'validity'): ATTEST.audit(**self.arguments())
            native.assert_not_called()

    def test_payload_and_key_shape_pin_or_signature_size_refuse_before_native(self):
        payload = self.release/'gateway/System.Private.CoreLib.dll'; original = payload.read_bytes()
        payload.write_bytes(original+b'changed')
        with patch.object(ATTEST.INPUTS, 'NativeOpenSSL', side_effect=AssertionError('early native')) as native:
            with self.assertRaisesRegex(ValueError,'payload commitment'): ATTEST.audit(**self.arguments())
            native.assert_not_called()
        payload.write_bytes(original)
        original_key, original_signature = self.public.read_bytes(), self.signature.read_bytes()
        for fault in ('shape','pin','signature'):
            self.public.write_bytes(original_key); self.signature.write_bytes(original_signature)
            arguments = self.arguments()
            if fault == 'shape':
                self.public.write_bytes(b'X'+original_key[1:]); arguments['public_key_sha256']=hashlib.sha256(self.public.read_bytes()).hexdigest()
            elif fault == 'pin': arguments['public_key_sha256']='0'*64
            else: self.signature.write_bytes(original_signature[:-1])
            with self.subTest(fault=fault), patch.object(ATTEST.INPUTS,'NativeOpenSSL',side_effect=AssertionError('early native')) as native:
                with self.assertRaisesRegex(ValueError,'Ed25519'): ATTEST.audit(**arguments)
                native.assert_not_called()

    def test_sealed_native_inputs_and_post_verification_source_drift_refuse(self):
        original = ATTEST.INPUTS.NativeOpenSSL.run
        for fault in ('payload', 'signature'):
            self.sign(); payload=self.release/'gateway/System.Private.CoreLib.dll'; old=payload.read_bytes(); calls=[]
            def observed(native, arguments, *args, **kwargs):
                self.assertEqual(native.environment, ATTEST.INPUTS.ENVIRONMENT)
                if arguments[0] == 'pkeyutl':
                    fds=kwargs['descriptors']; self.assertEqual(len(fds),3)
                    for fd in fds:
                        self.assertEqual(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&ATTEST.INPUTS.SEALS,ATTEST.INPUTS.SEALS)
                    self.assertEqual(os.pread(fds[2],16385,0),ATTEST.DOMAIN+self.attestation.read_bytes())
                result=original(native,arguments,*args,**kwargs);calls.append(arguments)
                if arguments[0] == 'pkeyutl':
                    if fault == 'payload': payload.write_bytes(old+b'post-verification-change')
                    else: self.signature.write_bytes(b'0'*64)
                return result
            with self.subTest(fault=fault), patch.object(ATTEST.INPUTS.NativeOpenSSL,'run',observed):
                with self.assertRaises(ValueError): ATTEST.audit(**self.arguments())
            self.assertEqual(len(calls),2); payload.write_bytes(old)

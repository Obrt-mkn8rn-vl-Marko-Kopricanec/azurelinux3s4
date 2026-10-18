"""Original complete private plans, synthetic key rings and real ephemeral RSA."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_email_keys',ROOT/'Bootstrap/email_key_preflight.py')
EMAIL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EMAIL)
CAPTURES = []


class EmailKeyPreflightTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        cls.temp_keys = tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        cls.addClassCleanup(cls.temp_keys.cleanup)
        folder = Path(cls.temp_keys.name); folder.chmod(0o700); cls.keys = {}
        cls.pin = hashlib.sha256(Path(EMAIL.INPUTS.OPENSSL).read_bytes()).hexdigest()
        for name in ('oauth','dkim'):
            private = folder/(name+'.pem'); public = folder/(name+'.der')
            for args in (['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(private)],
                         ['pkey','-in',str(private),'-pubout','-outform','DER','-out',str(public)]):
                child = subprocess.run([EMAIL.INPUTS.OPENSSL,*args],env=EMAIL.INPUTS.ENVIRONMENT,
                                       capture_output=True,timeout=10)
                if child.returncode: raise AssertionError('Ephemeral RSA fixture failed: '+child.stderr.decode())
            cls.keys[name] = {'pem':private.read_bytes(),'spki':public.read_bytes(),
                              'der':EMAIL.INPUTS.pem_blocks(private.read_bytes(),{'PRIVATE KEY'},1)[0]}

    def setUp(self):
        super().setUp()
        self.signing_pins = {name:hashlib.sha256(value['spki']).hexdigest() for name,value in self.keys.items()}
        for role in ('worker','gateway'):
            folder = self.root/'etc/mk8.email'/role
            (folder/'messaging-key.txt').write_bytes(base64.b64encode(b'P'*32)+b'\n')
            (folder/'messaging-decrypt-old.txt').write_bytes(base64.b64encode(b'O'*32))
        folder = self.root/'etc/mk8.email/worker'
        (folder/'mfa-key.txt').write_bytes(base64.b64encode(b'M'*32)+b'\n')
        for name,leaf in EMAIL.SIGNERS.items(): (folder/leaf).write_bytes(self.keys[name]['pem'])

    def configuration(self,role,value):
        raw = fixture.encoded(value); (self.root/'etc/mk8.email'/(role+'.json')).write_bytes(raw)
        self.documents['mk8.email']['configuration'][role+'.json'] = hashlib.sha256(raw).hexdigest()
        self.seal('mk8.email'); self.manifest_file.write_bytes(fixture.encoded(self.value))

    def arguments(self):
        return dict(private_root=self.root,manifest='/manifest.json',openssl_sha256=self.pin,signing_keys=self.signing_pins)

    def cli(self):
        command = [sys.executable,'-I','-B',str(ROOT/'Bootstrap/email_key_preflight.py'),
                   '--root',str(self.root),'--manifest','/manifest.json','--openssl-sha256',self.pin]
        for name,pin in self.signing_pins.items(): command.extend(('--'+name+'-public-key-sha256',pin))
        return subprocess.run(command,capture_output=True,timeout=30)

    def test_complete_cli_checks_role_rotation_key_material_and_pinned_signers_without_writes(self):
        # Either role can produce with a different active ID while both can read
        # the same complete ring. Original textual LF differences stay intact.
        folder = self.root/'etc/mk8.email/gateway'; path = self.root/'etc/mk8.email/gateway.json'
        value = json.loads(path.read_bytes()); value['Messaging']['EncryptionKeyId'] = 'old'
        value['Messaging']['DecryptionKeys'] = [{'Id':'primary','KeyFile':
            '/run/credentials/mk8-email-gateway.service/messaging-decrypt-primary.txt'}]
        (folder/'messaging-key.txt').write_bytes(base64.b64encode(b'O'*32))
        (folder/'messaging-decrypt-primary.txt').write_bytes(base64.b64encode(b'P'*32))
        (folder/'messaging-decrypt-primary.txt').chmod(0o600)
        self.configuration('gateway',value); before = self.snapshot(); child = self.cli()
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result['messaging_key_ids'],['old','primary'])
        self.assertEqual(result['active_key_ids'],{'worker':'primary','gateway':'old'})
        self.assertTrue(result['mfa_key_checked']); self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual([row['public_spki_sha256'] for row in result['signing_keys']],list(self.signing_pins.values()))
        self.assertEqual([row['actual_returncode'] for row in result['openssl']['commands']],[0]*5)
        self.assertEqual(result['signing_keys'][0]['jwk_thumbprint_sha256'],
                         EMAIL.jwk_thumbprint(*EMAIL.KEYS.rsa_public(self.keys['oauth']['spki'])))
        for raw in (self.keys['oauth']['pem'],base64.b64encode(b'P'*32),base64.b64encode(b'M'*32)):
            self.assertNotIn(raw,child.stdout)
        self.assertEqual(self.snapshot(),before); self.assertFalse((self.root/'var').exists())
        CAPTURES.append(result)

    def test_complete_late_symmetric_rows_and_role_ring_disagreement_refuse_before_native(self):
        path = self.root/'etc/mk8.email/gateway/messaging-decrypt-old.txt'; original = path.read_bytes()
        variants = (b'bad',base64.b64encode(b'O'*31),original+b'\n\n',original+b'\r\n',
                    original[:10]+b' '+original[10:],base64.b64encode(b'X'*32),original[:-2]+b'9=')
        for raw in variants:
            path.write_bytes(raw); before = self.snapshot()
            with self.subTest(raw_length=len(raw)),patch.object(EMAIL.INPUTS,'NativeOpenSSL',side_effect=AssertionError('early crypto')) as native:
                with self.assertRaises(ValueError): EMAIL.audit(**self.arguments())
                native.assert_not_called()
            self.assertEqual(self.snapshot(),before)
        path.write_bytes(original)
        worker = self.root/'etc/mk8.email/worker.json'; value = json.loads(worker.read_bytes())
        value['OAuth'] = {}; value['Mfa'] = {}; value['Dkim'] = {}; self.configuration('worker',value)
        self.signing_pins = {}; result = EMAIL.audit(**self.arguments())
        self.assertEqual(result['signing_keys'],[]); self.assertFalse(result['mfa_key_checked'])
        self.assertEqual(len(result['openssl']['commands']),1)
        self.signing_pins = {'oauth':'0'*64}
        with patch.object(EMAIL.INPUTS,'NativeOpenSSL',side_effect=AssertionError('unused pin')) as native:
            with self.assertRaisesRegex(ValueError,'pin set'): EMAIL.audit(**self.arguments())
            native.assert_not_called()

    def test_rsa_representation_pin_and_actual_invalid_private_components_refuse(self):
        path = self.root/'etc/mk8.email/worker/dkim-key.pem'; original = path.read_bytes()
        encoded = base64.b64encode(self.keys['dkim']['der']+b'x')
        trailing = b'-----BEGIN PRIVATE KEY-----\n'+b'\n'.join(encoded[n:n+64] for n in range(0,len(encoded),64))+b'\n-----END PRIVATE KEY-----\n'
        for raw in (original*2,original.replace(b'PRIVATE KEY',b'RSA PRIVATE KEY'),
                    trailing):
            path.write_bytes(raw)
            with self.subTest(raw_length=len(raw)),patch.object(EMAIL.INPUTS,'NativeOpenSSL',side_effect=AssertionError('shape bypass')) as native:
                with self.assertRaises(ValueError): EMAIL.audit(**self.arguments())
                native.assert_not_called()
        for raw in (b'\x02\x00', b'\x02\x01\x00', b'\x02\x01\x80', b'\x02\x02\x00\x01',
                    b'\x02\x81\x01\x01', b'\x02\x82\x00\x80'+b'x'*128, b'\x02\x80\x00\x00'):
            with self.subTest(integer=raw[:6]),self.assertRaises(ValueError): EMAIL.KEYS.positive_integer(raw,0)
        with self.assertRaises(ValueError): EMAIL.KEYS.rsa_public(self.keys['dkim']['spki']+b'x')
        path.write_bytes(original); self.signing_pins['dkim'] = '0'*64
        child = self.cli()
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Private Email key preflight refused\n'))
        self.signing_pins['dkim'] = hashlib.sha256(self.keys['dkim']['spki']).hexdigest()
        corrupt = bytearray(self.keys['dkim']['der']); corrupt[-1] ^= 1
        encoded = base64.b64encode(corrupt)
        path.write_bytes(b'-----BEGIN PRIVATE KEY-----\n'+b'\n'.join(encoded[n:n+64] for n in range(0,len(encoded),64))+b'\n-----END PRIVATE KEY-----\n')
        calls = []; run = EMAIL.INPUTS.NativeOpenSSL.run
        def observed(native,arguments,*args,**kwargs):
            try: return run(native,arguments,*args,**kwargs)
            finally: calls.extend(native.commands[-1:])
        with patch.object(EMAIL.INPUTS.NativeOpenSSL,'run',observed):
            with self.assertRaisesRegex(ValueError,'OpenSSL check refused'): EMAIL.audit(**self.arguments())
        self.assertTrue(any(row['actual_returncode'] != 0 for row in calls))

    def test_faulty_complete_source_commitments_and_missing_last_credential_refuse_before_crypto(self):
        good = EMAIL.PREFLIGHT.preflight(self.root,'/manifest.json',include_candidate=True)
        for fault in ('commitment','path','missing','duplicate','manifest'):
            bad = copy.deepcopy(good); rows = bad['candidate']['email_credentials'][1]['inputs']
            row = next(row for row in rows if row['id']=='messaging-decrypt-old.txt')
            if fault=='commitment': row['sha256'] = '0'*64
            elif fault=='path': row['source'] = '/etc/foreign/old.txt'
            elif fault=='missing': rows.remove(row)
            elif fault=='duplicate': rows.append(dict(row))
            else: bad['manifest_sha256'] = '0'*64
            with self.subTest(fault=fault),patch.object(EMAIL.PREFLIGHT,'preflight',return_value=bad), \
                    patch.object(EMAIL.INPUTS,'NativeOpenSSL',side_effect=AssertionError('unbound crypto')) as native:
                with self.assertRaises(ValueError): EMAIL.audit(**self.arguments())
                native.assert_not_called()

    def test_post_native_change_of_original_key_or_unrelated_credential_withholds_receipt(self):
        run = EMAIL.INPUTS.NativeOpenSSL.run
        for path in (self.root/'etc/mk8.email/gateway/messaging-key.txt',self.root/'etc/mk8.dns/controller/key.pem'):
            original = path.read_bytes(); calls = []
            def changed(native,arguments,*args,**kwargs):
                result = run(native,arguments,*args,**kwargs); calls.append(arguments)
                if len(calls)==5: path.write_bytes(original+b'\n')
                return result
            before = self.snapshot()
            with self.subTest(path=path.name),patch.object(EMAIL.INPUTS.NativeOpenSSL,'run',changed):
                with self.assertRaisesRegex(ValueError,'application plan changed'): EMAIL.audit(**self.arguments())
            self.assertEqual(len(calls),5); path.write_bytes(original)
            self.assertEqual(self.snapshot(),before); self.assertFalse((self.root/'var').exists())

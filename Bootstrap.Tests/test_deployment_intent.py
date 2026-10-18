"""Signed complete synthetic input graphs with real local Ed25519 verification."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture
import test_release_attestation as material


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_deployment_intent',ROOT/'Bootstrap/deployment_intent.py')
INTENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTENT)
CAPTURES = []


class DeploymentIntentTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        material.ReleaseAttestationTests.setUpClass()
        cls.addClassCleanup(material.ReleaseAttestationTests.doClassCleanups)
        cls.keys = material.ReleaseAttestationTests.keys
        cls.pin = material.ReleaseAttestationTests.openssl_pin

    def setUp(self):
        super().setUp()
        self.current = 1792335600
        self.description = INTENT.collect(self.root,'/manifest.json')
        self.public = self.root/'signer.der';self.public.write_bytes((self.keys/'signer.der').read_bytes());self.public.chmod(0o600)
        self.key_sha = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.attestation = self.root/'intent-attestation.json';self.signature = self.root/'intent-signature.ed25519'
        self.envelope = {'schema':1,'purpose':'azurelinux3s4-deployment-intent',
                         'intent_sha256':self.description['intent_sha256'],'key_sha256':self.key_sha,'sequence':7,
                         'not_before':self.current-60,'not_after':self.current+3600}
        self.sign()

    def sign(self,domain=None):
        raw = INTENT.encoded(self.envelope);self.attestation.write_bytes(raw);self.attestation.chmod(0o600)
        message = self.root/'signing-message';message.write_bytes((INTENT.DOMAIN if domain is None else domain)+raw);message.chmod(0o600)
        material.ReleaseAttestationTests.native('pkeyutl','-sign','-rawin','-inkey',str(self.keys/'signer.pem'),
                                               '-in',str(message),'-out',str(self.signature))
        self.signature.chmod(0o600);message.unlink()

    def arguments(self):
        return dict(private_root=self.root,manifest='/manifest.json',attestation=self.attestation,signature=self.signature,
                    public_key=self.public,public_key_sha256=self.key_sha,openssl_sha256=self.pin,minimum_sequence=7,at=self.current)

    def cli(self,describe=False):
        args = self.arguments();args['root'] = args.pop('private_root')
        command = [sys.executable,'-I','-B',str(ROOT/'Bootstrap/deployment_intent.py')]
        if describe: args = {'root':self.root,'manifest':'/manifest.json'}
        for name,value in args.items():command.extend(('--'+name.replace('_','-'),str(value)))
        if describe:command.append('--describe')
        return subprocess.run(command,capture_output=True,timeout=30)

    def test_complete_signed_intent_binds_every_selected_source_and_both_generated_file_sets(self):
        before = self.snapshot();child = self.cli()
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result = json.loads(child.stdout);intent = result['intent']
        self.assertTrue(all(result['checks'].values()));self.assertTrue(all(value is False for value in result['authority'].values()))
        expected = {'/'+name for name in before if name.startswith('etc/')} | {'/manifest.json'}
        self.assertEqual({row['file'] for row in intent['protected_inputs']},expected)
        for row in intent['protected_inputs']:
            self.assertEqual(row['sha256'],before[row['file'][1:]][0]);self.assertEqual(row['mode'],'0600')
        self.assertEqual([row['application'] for row in intent['releases']],list(self.n['DEP_APPS']))
        self.assertEqual(len(intent['deployment_files']),5);self.assertEqual(len(intent['application_files']),11)
        self.assertEqual(result['intent_sha256'],hashlib.sha256(INTENT.encoded(intent)).hexdigest())
        self.assertEqual([row['actual_returncode'] for row in result['openssl']['commands']],[0,0])
        self.assertEqual(self.snapshot(),before);self.assertFalse((self.root/'var').exists())
        self.assertNotIn(b'finite opaque Email input',child.stdout);self.assertNotIn(b'finite-model-only-password',child.stdout)
        described = self.cli(True)
        self.assertEqual((described.returncode,described.stderr),(0,b''))
        self.assertEqual(json.loads(described.stdout)['intent'],intent)
        # Qualified relocation preserves logical bytes, never incidental inode
        # identities. It is not acceptance of a different source during a run.
        with tempfile.TemporaryDirectory(dir=Path.home()/'.cache') as parent:
            copied = Path(parent)/'copy';shutil.copytree(self.root,copied)
            other = INTENT.describe(copied,'/manifest.json')
            self.assertEqual(other['intent'],intent)
            self.assertNotEqual(other['observations'],result['observations'])
        CAPTURES.append({'result':result,'public_key_hex':self.public.read_bytes().hex(),
                         'signature_hex':self.signature.read_bytes().hex(),'envelope':self.attestation.read_text()})

    def test_changed_nested_originals_and_late_census_discrepancies_refuse_before_crypto(self):
        for path in (self.root/'etc/mk8.email/gateway/messaging-decrypt-old.txt',self.root/'etc/mk8.dns/controller/key.pem'):
            raw = path.read_bytes();path.write_bytes(raw+b'changed')
            with self.subTest(source=path.name),patch.object(INTENT.INPUTS,'NativeOpenSSL',side_effect=AssertionError('unsigned new source')) as native:
                with self.assertRaisesRegex(ValueError,'exact deployment intent'):INTENT.audit(**self.arguments())
                native.assert_not_called()
            path.write_bytes(raw)
        apps = INTENT.PREFLIGHT.preflight(self.root,'/manifest.json',include_candidate=True,include_sources=True)
        deployment = INTENT.PREFLIGHT.preflight(self.root,'/manifest.json','deployment',True,True)
        for fault in ('missing','duplicate','commitment','generated','release'):
            bad = copy.deepcopy(apps)
            if fault=='missing':bad['protected_inputs'].pop()
            elif fault=='duplicate':bad['protected_inputs'].append(dict(bad['protected_inputs'][-1]))
            elif fault=='commitment':bad['protected_inputs'][-2]['sha256'] = '0'*64
            elif fault=='generated':bad['publication']['files'][-1]['sha256'] = '0'*64
            else:bad['candidate']['releases'][-1]['manifest_sha256'] = '0'*64
            def fake(*args,**kwargs):return deployment if len(args)>2 and args[2]=='deployment' else bad
            with self.subTest(fault=fault),patch.object(INTENT.PREFLIGHT,'preflight',side_effect=fake), \
                    patch.object(INTENT.INPUTS,'NativeOpenSSL',side_effect=AssertionError('faulty source graph')) as native:
                with self.assertRaises(ValueError):INTENT.audit(**self.arguments())
                native.assert_not_called()

    def test_exact_envelope_purpose_key_sequence_and_time_policy_precede_native(self):
        original = copy.deepcopy(self.envelope)
        variants = (('schema',True),('purpose','azurelinux3s4-application-release'),('intent_sha256','0'*64),
                    ('key_sha256','0'*64),('sequence',6),('sequence',True),('not_before',self.current+1),
                    ('not_after',self.current),('not_after',self.current+32*86400),('extra',0))
        for name,value in variants:
            changed = dict(original);changed[name] = value;self.attestation.write_bytes(INTENT.encoded(changed))
            with self.subTest(field=name,value=value),patch.object(INTENT.INPUTS,'NativeOpenSSL',side_effect=AssertionError('inadmissible envelope')) as native:
                with self.assertRaises(ValueError):INTENT.audit(**self.arguments())
                native.assert_not_called()
        raw = INTENT.encoded(original)
        for altered in (raw+b'\n',raw.replace(b'"schema":1',b'"schema":1,"schema":1'),raw.replace(b'"sequence":7',b'"sequence":NaN')):
            self.attestation.write_bytes(altered)
            with patch.object(INTENT.INPUTS,'NativeOpenSSL',side_effect=AssertionError('noncanonical envelope')) as native:
                with self.assertRaises(ValueError):INTENT.audit(**self.arguments())
                native.assert_not_called()

    def test_bad_signature_and_release_protocol_signature_refuse_actual_native_verification(self):
        raw = bytearray(self.signature.read_bytes());raw[-1]^=1;self.signature.write_bytes(raw)
        before = self.snapshot();child = self.cli()
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Private deployment intent refused\n'))
        self.assertEqual(self.snapshot(),before)
        self.sign(INTENT.ATTEST.DOMAIN);calls=[];run=INTENT.INPUTS.NativeOpenSSL.run
        def observed(native,args,*pos,**kwargs):
            try:return run(native,args,*pos,**kwargs)
            finally:calls.extend(native.commands[-1:])
        with patch.object(INTENT.INPUTS.NativeOpenSSL,'run',observed):
            with self.assertRaisesRegex(ValueError,'OpenSSL check refused'):INTENT.audit(**self.arguments())
        self.assertEqual([row['actual_returncode'] for row in calls],[0,1])

    def test_post_signature_original_changes_or_last_protected_reread_prevent_receipts(self):
        run=INTENT.INPUTS.NativeOpenSSL.run
        for path in (self.root/'etc/mk8.email/worker/mfa-key.txt',self.attestation):
            original=path.read_bytes();calls=[]
            def changed(native,args,*pos,**kwargs):
                result=run(native,args,*pos,**kwargs);calls.append(args)
                if len(calls)==2:path.write_bytes(original+b'\n')
                return result
            with self.subTest(path=path.name),patch.object(INTENT.INPUTS.NativeOpenSSL,'run',changed):
                with self.assertRaises(ValueError):INTENT.audit(**self.arguments())
            self.assertEqual(len(calls),2);path.write_bytes(original)
        library=INTENT.PREFLIGHT.shipped_library;target=self.root/'etc/mk8.email/worker/mfa-key.txt';original=target.read_bytes()
        def changed_library():
            namespace,software=library();planner=namespace['application_publication_plan']
            def planned(*args):
                result=planner(*args);target.write_bytes(original+b'\n');return result
            namespace['application_publication_plan']=planned
            return namespace,software
        with patch.object(INTENT.PREFLIGHT,'shipped_library',side_effect=changed_library):
            with self.assertRaisesRegex(ValueError,'protected original source changed'):
                INTENT.PREFLIGHT.preflight(self.root,'/manifest.json',include_sources=True)
        self.assertFalse((self.root/'var').exists())

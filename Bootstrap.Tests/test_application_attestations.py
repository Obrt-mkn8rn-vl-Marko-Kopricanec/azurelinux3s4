"""Four exact private release signatures with whole-plan refusal controls."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import test_deployment_releases as fixture
import test_release_attestation as material


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_application_attestations', ROOT/'Bootstrap/application_attestations.py')
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)
CAPTURES = []


class ApplicationAttestationsTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        material.ReleaseAttestationTests.setUpClass()
        cls.addClassCleanup(material.ReleaseAttestationTests.doClassCleanups)
        cls.keys = material.ReleaseAttestationTests.keys
        cls.pin = material.ReleaseAttestationTests.openssl_pin

    def setUp(self):
        super().setUp()
        self.current = 1792335600
        self.public = self.root/'signer.der'
        self.public.write_bytes((self.keys/'signer.der').read_bytes()); self.public.chmod(0o600)
        self.key_sha = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.policy = self.root/'release-trust.json'
        self.trust = {'schema': 1, 'applications': {}}
        for app in self.n['DEP_APPS']:
            row = {'attestation': str(self.root/(app+'.attestation.json')),
                   'signature': str(self.root/(app+'.signature.ed25519')),
                   'public_key': str(self.public), 'public_key_sha256': self.key_sha, 'minimum_sequence': 9}
            self.trust['applications'][app] = row
            envelope = {'schema': 1, 'purpose': 'azurelinux3s4-application-release', 'application': app,
                        **self.value['releases'][app], 'key_sha256': self.key_sha, 'sequence': 9,
                        'not_before': self.current-60, 'not_after': self.current+3600}
            raw = fixture.encoded(envelope)
            source = Path(row['attestation']); source.write_bytes(raw); source.chmod(0o600)
            message = self.root/'signing-input'; message.write_bytes(APP.ATTEST.DOMAIN+raw); message.chmod(0o600)
            material.ReleaseAttestationTests.native('pkeyutl','-sign','-rawin','-inkey',str(self.keys/'signer.pem'),
                                                    '-in',str(message),'-out',row['signature'])
            Path(row['signature']).chmod(0o600); message.unlink()
        self.save_policy()

    def save_policy(self):
        raw=fixture.encoded(self.trust); self.policy.write_bytes(raw); self.policy.chmod(0o600)
        self.policy_sha=hashlib.sha256(raw).hexdigest()

    def arguments(self):
        return dict(private_root=self.root, manifest='/manifest.json', policy=self.policy,
                    policy_sha256=self.policy_sha, openssl_sha256=self.pin, at=self.current)

    def cli(self):
        args=self.arguments(); args['root']=args.pop('private_root')
        command=[sys.executable,'-I','-B',str(ROOT/'Bootstrap/application_attestations.py')]
        for name,value in args.items(): command.extend(('--'+name.replace('_','-'),str(value)))
        return subprocess.run(command,capture_output=True,timeout=30)

    def test_complete_cli_verifies_all_four_signatures_and_preserves_every_private_input(self):
        before=self.snapshot(); child=self.cli()
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result=json.loads(child.stdout)
        self.assertEqual([row['application'] for row in result['applications']],list(self.n['DEP_APPS']))
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(result['trust_policy']['sha256'],self.policy_sha)
        self.assertEqual(result['manifest_sha256'],hashlib.sha256(self.manifest_file.read_bytes()).hexdigest())
        self.assertEqual(len(result['files']),14)
        for row in result['applications']:
            self.assertTrue(row['source_commitments_supplied'])
            self.assertEqual(row['declaration'],self.value['releases'][row['application']])
            self.assertEqual([item['actual_returncode'] for item in row['openssl']['commands']],[0,0])
            self.assertTrue(all(value is False for value in row['authority'].values()))
        self.assertNotIn(b'PRIVATE KEY',child.stdout)
        self.assertEqual(self.snapshot(),before);self.assertFalse((self.root/'var').exists())
        CAPTURES.append({'scope':'FOUR REAL ED25519 VERIFICATIONS OVER SYNTHETIC COMPLETE RELEASES','result':result})

    def test_complete_late_policy_and_envelope_admission_precedes_any_native_verification(self):
        original=copy.deepcopy(self.trust)
        for fault in ('missing','extra','floor','path','duplicate','pin','envelope'):
            self.trust=copy.deepcopy(original)
            row=self.trust['applications']['mk8.email']; source=Path(row['attestation']); raw=source.read_bytes()
            if fault=='missing': del self.trust['applications']['mk8.email']
            elif fault=='extra': row['fallback_key']='not admitted'
            elif fault=='floor': row['minimum_sequence']=True
            elif fault=='path': row['signature']='/tmp/../unexpected'
            elif fault=='duplicate': row['signature']=self.trust['applications']['mk8.sava']['signature']
            elif fault=='pin': row['public_key_sha256']='0'*64
            else:
                changed=json.loads(raw);changed['sequence']=8;source.write_bytes(fixture.encoded(changed))
            self.save_policy();before=self.snapshot()
            with self.subTest(fault=fault),patch.object(APP.ATTEST,'audit',side_effect=AssertionError('early native')) as verifier:
                with self.assertRaises(ValueError):APP.audit(**self.arguments())
                verifier.assert_not_called()
            self.assertEqual(self.snapshot(),before);source.write_bytes(raw)
        self.trust=original;self.save_policy()
        arguments=self.arguments();arguments['policy_sha256']='0'*64
        with patch.object(APP.PREFLIGHT,'preflight',side_effect=AssertionError('unbound policy')) as planner:
            with self.assertRaisesRegex(ValueError,'caller pin'):APP.audit(**arguments)
            planner.assert_not_called()

    def test_bad_late_signature_withholds_whole_cli_receipt_without_writes(self):
        path=Path(self.trust['applications']['mk8.email']['signature'])
        raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
        before=self.snapshot();child=self.cli()
        self.assertEqual((child.returncode,child.stdout,child.stderr),
                         (75,b'',b'Private application attestation preflight refused\n'))
        self.assertEqual(self.snapshot(),before);self.assertFalse((self.root/'var').exists())

    def test_full_candidate_and_source_commitments_refuse_faulty_producer_or_between_phase_change(self):
        original=APP.PREFLIGHT.preflight(self.root,'/manifest.json',include_candidate=True)
        for fault in ('manifest','order','release'):
            bad=copy.deepcopy(original)
            if fault=='manifest':bad['manifest_sha256']='0'*64
            elif fault=='order':bad['candidate']['releases'].reverse()
            else:bad['candidate']['releases'][-1]['declaration']['tree']='0'*40
            with self.subTest(fault=fault),patch.object(APP.PREFLIGHT,'preflight',return_value=bad), \
                    patch.object(APP.ATTEST,'audit',side_effect=AssertionError('unbound candidate')) as verifier:
                with self.assertRaises(ValueError):APP.audit(**self.arguments())
                verifier.assert_not_called()
        audit=APP.ATTEST.audit;calls=[]
        def changed(**arguments):
            calls.append(arguments['app'])
            Path(arguments['signature']).write_bytes(b'X'*64)
            return audit(**arguments)
        with patch.object(APP.ATTEST,'audit',side_effect=changed), \
                patch.object(APP.ATTEST.INPUTS,'NativeOpenSSL',side_effect=AssertionError('changed source native')) as native:
            with self.assertRaisesRegex(ValueError,'source commitments'):APP.audit(**self.arguments())
            native.assert_not_called()
        self.assertEqual(calls,['mk8.sava'])

    def test_changes_after_all_signatures_prevent_final_receipt(self):
        paths=(self.root/'etc/mk8.email/worker/messaging-key.txt',self.policy,
               Path(self.trust['applications']['mk8.sava']['signature']))
        original=APP.ATTEST.audit
        for path in paths:
            raw=path.read_bytes();calls=[]
            def changed(**arguments):
                result=original(**arguments);calls.append(arguments['app'])
                if arguments['app']=='mk8.email':path.write_bytes(raw+b'\n')
                return result
            with self.subTest(path=path.name),patch.object(APP.ATTEST,'audit',side_effect=changed):
                with self.assertRaises(ValueError):APP.audit(**self.arguments())
            self.assertEqual(calls,list(self.n['DEP_APPS']));path.write_bytes(raw)
            self.assertFalse((self.root/'var').exists())

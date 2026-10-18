"""Real ephemeral P256 keys with full private plan and key-source correspondence."""

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


ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('private_dns_keys',ROOT/'Bootstrap/dns_key_preflight.py')
DNS=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)
CAPTURES=[]


class DnsKeyPreflightTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        cls.temp_keys=tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        cls.addClassCleanup(cls.temp_keys.cleanup)
        folder=Path(cls.temp_keys.name);folder.chmod(0o700)
        cls.pin=hashlib.sha256(Path(DNS.INPUTS.OPENSSL).read_bytes()).hexdigest();cls.keys={}
        for name,curve in (('publisher','P-256'),('other','P-256'),('zone','P-256'),('wrongcurve','P-384')):
            private=folder/(name+'.pem');public=folder/(name+'.public.pem')
            for args in (['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:'+curve,'-out',str(private)],
                         ['pkey','-in',str(private),'-pubout','-out',str(public)]):
                child=subprocess.run([DNS.INPUTS.OPENSSL,*args],env=DNS.INPUTS.ENVIRONMENT,capture_output=True,timeout=10)
                if child.returncode:raise AssertionError('Ephemeral DNS key fixture failed: '+child.stderr.decode())
            cls.keys[name]={'pem':private.read_bytes(),'public':public.read_bytes(),
                            'der':DNS.INPUTS.pem_blocks(private.read_bytes(),{'PRIVATE KEY'},1)[0],
                            'spki':DNS.INPUTS.pem_blocks(public.read_bytes(),{'PUBLIC KEY'},1)[0]}

    def setUp(self):
        super().setUp()
        self.controller=self.root/'etc/mk8.dns/controller/key.pem'
        self.replica=self.root/'etc/mk8.dns/authoritative-replica/key.pem'
        self.controller.write_bytes(self.keys['publisher']['pem']);self.replica.write_bytes(self.keys['publisher']['public'])
        self.public_pin=hashlib.sha256(self.keys['publisher']['spki']).hexdigest()
        self.zone_id='11111111-1111-1111-1111-111111111111';self.zone_pins={}
        self.zone=self.root/'etc/mk8.dns/controller'/('zone-'+self.zone_id+'.pk8')

    def enable_zone(self):
        self.zone.write_bytes(self.keys['zone']['der']);self.zone.chmod(0o600)
        path=self.root/'etc/mk8.dns/control-plane.json';value=json.loads(path.read_bytes())
        value['Zones'][0]['SigningKeyFile']='/run/mk8.dns/controller/inputs/'+self.zone.name
        raw=fixture.encoded(value);path.write_bytes(raw)
        self.documents['mk8.dns']['configuration']['control-plane.json']=hashlib.sha256(raw).hexdigest()
        self.seal('mk8.dns');self.manifest_file.write_bytes(fixture.encoded(self.value))
        self.zone_pins={self.zone_id:hashlib.sha256(self.keys['zone']['spki']).hexdigest()}

    def arguments(self):
        return dict(private_root=self.root,manifest='/manifest.json',openssl_sha256=self.pin,
                    publication_public_key_sha256=self.public_pin,zone_keys=self.zone_pins)

    def cli(self):
        args=self.arguments();zones=args.pop('zone_keys');args['root']=args.pop('private_root')
        command=[sys.executable,'-I','-B',str(ROOT/'Bootstrap/dns_key_preflight.py')]
        for name,value in args.items():command.extend(('--'+name.replace('_','-'),str(value)))
        for name,value in zones.items():command.extend(('--zone-key',name+'='+value))
        return subprocess.run(command,capture_output=True,timeout=30)

    def test_complete_cli_matches_publication_pair_and_configured_zone_pin_without_writes(self):
        self.enable_zone();before=self.snapshot();child=self.cli()
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result=json.loads(child.stdout)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(result['publication_public_spki_sha256'],self.public_pin)
        self.assertEqual(result['zone_keys'],[{'zone_id':self.zone_id,'source':'/etc/mk8.dns/controller/'+self.zone.name,
                         'algorithm_declaration':13,'public_spki_sha256':self.zone_pins[self.zone_id],
                         'public_xy_sha256':hashlib.sha256(self.keys['zone']['spki'][-64:]).hexdigest()}])
        self.assertEqual([row['actual_returncode'] for row in result['openssl']['commands']],[0]*6)
        self.assertNotIn(b'PRIVATE KEY',child.stdout)
        self.assertNotIn(base64.b64encode(self.keys['publisher']['der']),child.stdout)
        self.assertEqual(self.snapshot(),before);self.assertFalse((self.root/'var').exists())
        CAPTURES.append(result)

    def test_unsigned_zone_profile_and_mismatched_native_publication_pair_or_pins(self):
        before=self.snapshot();result=DNS.audit(**self.arguments())
        self.assertEqual(result['zone_keys'],[])
        self.assertEqual(len(result['openssl']['commands']),4);self.assertEqual(self.snapshot(),before)
        self.replica.write_bytes(self.keys['other']['public'])
        self.public_pin=hashlib.sha256(self.keys['other']['spki']).hexdigest()
        with self.assertRaisesRegex(ValueError,'controller and replica keys differ'):DNS.audit(**self.arguments())
        child=self.cli()
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Private DNS key preflight refused\n'))
        self.replica.write_bytes(self.keys['publisher']['public']);self.public_pin='0'*64
        with patch.object(DNS.INPUTS,'NativeOpenSSL',side_effect=AssertionError('unbound key')) as native:
            with self.assertRaisesRegex(ValueError,'explicit pin'):DNS.audit(**self.arguments())
            native.assert_not_called()

    def test_complete_role_curve_and_pkcs8_shapes_refuse_before_native(self):
        self.enable_zone()
        variants=((self.replica,self.keys['publisher']['pem']),
                  (self.controller,self.keys['publisher']['public']),
                  (self.controller,self.keys['wrongcurve']['pem']),
                  (self.zone,self.keys['zone']['der']+b'trailing'),
                  (self.zone,self.keys['zone']['pem']),
                  (self.replica,self.keys['publisher']['public']*2))
        for path,raw in variants:
            old=path.read_bytes();path.write_bytes(raw);before=self.snapshot()
            with self.subTest(path=path.name,raw=raw[:15]),patch.object(DNS.INPUTS,'NativeOpenSSL',side_effect=AssertionError('early crypto')) as native:
                with self.assertRaises(ValueError):DNS.audit(**self.arguments())
                native.assert_not_called()
            self.assertEqual(self.snapshot(),before);path.write_bytes(old)
        for pins in ({},{**self.zone_pins,'22222222-2222-2222-2222-222222222222':'0'*64}):
            args=self.arguments();args['zone_keys']=pins
            with patch.object(DNS.INPUTS,'NativeOpenSSL',side_effect=AssertionError('early missing pin')) as native:
                with self.assertRaisesRegex(ValueError,'pin set'):DNS.audit(**args)
                native.assert_not_called()
        args=self.arguments();args['zone_keys']={self.zone_id:'0'*64}
        with self.assertRaisesRegex(ValueError,'explicit zone pin'):DNS.audit(**args)

    def test_faulty_credential_commitment_path_or_missing_late_zone_refuses_before_crypto(self):
        self.enable_zone();candidate=DNS.PREFLIGHT.preflight(self.root,'/manifest.json',include_candidate=True)
        for fault in ('commitment','path','missing','manifest'):
            bad=copy.deepcopy(candidate)
            row=next(row for row in bad['candidate']['dns_credentials'][0]['inputs'] if row['id']==self.zone.name)
            if fault=='commitment':row['sha256']='0'*64
            elif fault=='path':row['source']='/etc/foreign/'+self.zone.name
            elif fault=='missing':bad['candidate']['dns_credentials'][0]['inputs'].remove(row)
            else:bad['manifest_sha256']='0'*64
            with self.subTest(fault=fault),patch.object(DNS.PREFLIGHT,'preflight',return_value=bad), \
                    patch.object(DNS.INPUTS,'NativeOpenSSL',side_effect=AssertionError('unbound crypto')) as native:
                with self.assertRaises(ValueError):DNS.audit(**self.arguments())
                native.assert_not_called()

    def test_malformed_private_point_fails_native_and_postcheck_source_change_prevents_receipt(self):
        self.enable_zone();raw=self.zone.read_bytes();changed=bytearray(raw);changed[-1]^=1
        self.zone.write_bytes(changed);calls=[];original=DNS.INPUTS.NativeOpenSSL.run
        def observed(native,arguments,*args,**kwargs):
            try:return original(native,arguments,*args,**kwargs)
            finally:calls.extend(native.commands[-1:])
        with patch.object(DNS.INPUTS.NativeOpenSSL,'run',observed):
            with self.assertRaisesRegex(ValueError,'OpenSSL check refused'):DNS.audit(**self.arguments())
        self.assertTrue(any(row['actual_returncode']!=0 for row in calls));self.zone.write_bytes(raw)
        for path in (self.replica,self.root/'etc/mk8.email/worker/messaging-key.txt'):
            old=path.read_bytes();seen=[]
            def modified(native,arguments,*args,**kwargs):
                result=original(native,arguments,*args,**kwargs);seen.append(arguments)
                if len(seen)==6:path.write_bytes(old+b'\n')
                return result
            with self.subTest(path=path.name),patch.object(DNS.INPUTS.NativeOpenSSL,'run',modified):
                with self.assertRaises(ValueError):DNS.audit(**self.arguments())
            self.assertEqual(len(seen),6);path.write_bytes(old)

"""Compile tiny owned ELF DATA, never load it; check exact symbol declarations."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_native_symbols',ROOT/'Bootstrap/native_closure.py')
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)
LIBRARY = 'libsymbol-model.so.1'
CAPTURES = []


def locations(raw):
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,header[6]+index*64) for index in range(header[12])]
    index=next(i for i,row in enumerate(sections) if row[1]==11)
    table=sections[index];version=next(row for row in sections if row[1]==0x6fffffff)
    return {'section':header[6]+index*64,'symbols':table[4],'count':table[5]//24,'versions':version[4]}


class NativeSymbolTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        cls.material=tempfile.TemporaryDirectory(dir=Path.home()/'.cache');cls.addClassCleanup(cls.material.cleanup)
        folder=Path(cls.material.name);folder.chmod(0o700)
        sources={'provider.c':'int model_value(void) { return 7; }\n',
                 'consumer.c':'extern int model_value(void);\nextern int optional_model(void) __attribute__((weak));\nint consumer_value(void) { return model_value() + (optional_model ? optional_model() : 0); }\n',
                 'versions.map':'MODEL_1.0 { global: model_value; local: *; };\n'}
        for name,raw in sources.items():(folder/name).write_text(raw)
        flags=['-std=c17','-Wall','-Wextra','-Werror','-pedantic','-fPIC','-shared','-nostdlib','-Wl,--hash-style=both']
        commands=[['/usr/bin/cc',*flags,str(folder/'provider.c'),'-Wl,-soname,'+LIBRARY,
                   '-Wl,--version-script='+str(folder/'versions.map'),'-o',str(folder/LIBRARY)],
                  ['/usr/bin/cc',*flags,str(folder/'consumer.c'),'-L'+str(folder),'-l:'+LIBRARY,
                   '-Wl,-z,defs','-o',str(folder/'consumer.so')],
                  ['/usr/bin/readelf','--dyn-syms','--wide','--version-info',str(folder/'consumer.so'),str(folder/LIBRARY)]]
        records=[]
        for command in commands:
            child=subprocess.run(command,capture_output=True,timeout=20,cwd=folder,
                                 env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(folder)})
            records.append({'command':command,'actual_returncode':child.returncode,
                            'stdout':child.stdout.decode('ascii'),'stderr':child.stderr.decode('ascii')})
            if child.returncode:raise AssertionError('Finite owned ELF compilation/inspection failed: '+child.stderr.decode())
        cls.provider=(folder/LIBRARY).read_bytes();cls.consumer=(folder/'consumer.so').read_bytes()
        if 'model_value@MODEL_1.0' not in records[-1]['stdout'] or 'optional_model' not in records[-1]['stdout']:
            raise AssertionError('Independent readelf declaration fixture mismatch')
        CAPTURES.append({'scope':'OWNED COMPILER/READELF PRODUCER INPUTS AND INERT OUTPUTS; NO OBJECT EXECUTION',
                         'sources':sources,'records':records,
                         'objects':{name:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'hex':raw.hex()}
                                    for name,raw in ((LIBRARY,cls.provider),('consumer.so',cls.consumer))}})

    def setUp(self):
        super().setUp();self.app='mk8.sava'
        for row in tuple(self.documents[self.app]['files']):
            if (self.folder(self.app)/row['path']).read_bytes().startswith(b'\x7fELF'):
                self.replace_file(row['path'],self.consumer,self.app)
        self.providers=self.root/'providers';self.providers.mkdir(mode=0o700)
        path=self.providers/LIBRARY;path.write_bytes(self.provider);path.chmod(0o400)
        self.plan={'schema':1,'files':[],'interpreters':{},'bindings':{role:{LIBRARY:{'source':'providers','path':LIBRARY}}
                   for role in self.n['REL_PROGRAMS'][self.app]}}
        self.save()

    def save(self):
        raw=(self.providers/LIBRARY).read_bytes()
        self.plan['files']=[{'path':LIBRARY,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}]
        path=self.providers/'providers.json'
        if path.exists():path.chmod(0o600)
        raw=fixture.encoded(self.plan);path.write_bytes(raw);path.chmod(0o400);self.pin=hashlib.sha256(raw).hexdigest()

    def arguments(self):
        return dict(app=self.app,**self.value['releases'][self.app],release=self.folder(self.app),
                    providers=self.providers,providers_sha256=self.pin,symbols=True)

    def test_complete_cli_binds_actual_compiler_symbols_versions_and_missing_weak_data_without_execution(self):
        before=self.snapshot();args=self.arguments();args.pop('symbols')
        command=[sys.executable,'-I','-B',str(ROOT/'Bootstrap/native_closure.py'),'--symbols']
        for name,value in args.items():command.extend(('--'+name.replace('_','-'),str(value)))
        child=subprocess.run(command,capture_output=True,timeout=20)
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result=json.loads(child.stdout);self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual([row['role'] for row in result['symbol_requirements']],['application','gateway'])
        for role in result['symbol_requirements']:
            strong=[row for row in role['requirements'] if not row['weak']]
            self.assertEqual(len(strong),4);self.assertEqual(role['missing_weak_symbols'],4)
            for row in strong:
                self.assertEqual((row['name'],row['version']['name']),('model_value','MODEL_1.0'))
                self.assertTrue(row['definition_available'])
                self.assertEqual([(x['source'],x['path']) for x in row['candidates']],[('providers',LIBRARY)])
        self.assertEqual(self.snapshot(),before);CAPTURES.append({'result':result})

    def test_matching_library_version_without_actual_visible_symbol_or_compatible_type_refuses(self):
        parsed=CLOSURE.NATIVE.elf_declarations(self.provider,True)
        symbol=next(row for row in parsed['dynamic_symbols']['symbols'] if row['name']=='model_value')
        positions=locations(self.provider);path=self.providers/LIBRARY
        for fault in ('hidden','wrong-type','unversioned','wrong-name','zero-value'):
            raw=bytearray(self.provider);offset=positions['symbols']+24*symbol['index']
            if fault=='hidden':struct.pack_into('<B',raw,offset+5,2)
            elif fault=='wrong-type':struct.pack_into('<B',raw,offset+4,0x11)
            elif fault=='unversioned':struct.pack_into('<H',raw,positions['versions']+2*symbol['index'],1)
            elif fault=='zero-value':struct.pack_into('<Q',raw,offset+8,0)
            else:struct.pack_into('<I',raw,offset,0)
            path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400);self.save();before=self.snapshot()
            with self.subTest(fault=fault),self.assertRaises(ValueError):CLOSURE.audit(**self.arguments())
            self.assertEqual(self.snapshot(),before)
        # A protected definition remains externally visible in this profile.
        raw=bytearray(self.provider);raw[positions['symbols']+24*symbol['index']+5]=3
        path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400);self.save()
        self.assertTrue(CLOSURE.audit(**self.arguments())['checks']['all_strong_named_symbol_requirements_have_candidates'])

    def test_complete_late_symbol_bounds_tags_version_indices_and_null_record_refuse(self):
        positions=locations(self.consumer);last=positions['symbols']+24*(positions['count']-1)
        for offset,layout,value in ((40,'<Q',2**64-1),(58,'<H',8),(60,'<H',0),
                (positions['section']+40,'<I',0),(positions['section']+44,'<I',positions['count']),
                (positions['section']+56,'<Q',16),(positions['symbols'],'<I',1),
                (last,'<I',0xffffffff),(last+5,'<B',4),(last+6,'<H',0xffff),
                (last+4,'<B',0x13),(last+4,'<B',0x14),(last+6,'<H',0xfff2),
                (positions['versions']+2*(positions['count']-1),'<H',0x7fff)):
            raw=bytearray(self.consumer);struct.pack_into(layout,raw,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):CLOSURE.NATIVE.elf_declarations(bytes(raw),True)
        with patch.object(CLOSURE.NATIVE.SYMBOLS,'SYMBOL_LIMIT',1):
            with self.assertRaises(ValueError):CLOSURE.NATIVE.elf_declarations(self.consumer,True)
        with self.assertRaises(ValueError):CLOSURE.NATIVE.elf_declarations(self.consumer,1)
        # An ordinary local row is deliberately constructed from the first global
        # row; the changed sh_info and VERSYM make ordering/version checks valid.
        for kind,section,visibility in ((4,1,0),(3,0xfff1,0),(0,1,3)):
            raw=bytearray(self.consumer);offset=positions['symbols']+24
            struct.pack_into('<I',raw,positions['section']+44,2)
            struct.pack_into('<BBH',raw,offset+4,kind,visibility,section)
            struct.pack_into('<H',raw,positions['versions']+2,0)
            with self.subTest(local=(kind,section,visibility)),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(bytes(raw),True)

    def test_default_version_visibility_weakness_and_tls_types_preserve_static_candidate_limits(self):
        release={'application/model':CLOSURE.NATIVE.elf_declarations(self.consumer,True)}
        providers={LIBRARY:CLOSURE.NATIVE.elf_declarations(self.provider,True)}
        roles=[{'role':'application','objects':[{'source':'release','path':'application/model'},
                                                {'source':'providers','path':LIBRARY}]}]
        bindings={'application':self.plan['bindings']['application']}
        required=next(row for row in release['application/model']['dynamic_symbols']['symbols'] if row['name']=='model_value')
        supplied=next(row for row in providers[LIBRARY]['dynamic_symbols']['symbols'] if row['name']=='model_value')
        required['version']=None;required['version_index']=1;supplied['version_hidden']=True
        with self.assertRaisesRegex(ValueError,'strong declared symbol'):
            CLOSURE.NATIVE.SYMBOLS.availability(roles,release,providers,bindings)
        supplied['version_hidden']=False
        self.assertEqual(CLOSURE.NATIVE.SYMBOLS.availability(roles,release,providers,bindings)[0]['missing_weak_symbols'],1)
        required['type']=6
        with self.assertRaisesRegex(ValueError,'strong declared symbol'):
            CLOSURE.NATIVE.SYMBOLS.availability(roles,release,providers,bindings)
        supplied['type']=6
        self.assertEqual(CLOSURE.NATIVE.SYMBOLS.availability(roles,release,providers,bindings)[0]['missing_weak_symbols'],1)
        optional=next(row for row in release['application/model']['dynamic_symbols']['symbols'] if row['name']=='optional_model')
        optional['binding']=1
        with self.assertRaisesRegex(ValueError,'optional_model'):
            CLOSURE.NATIVE.SYMBOLS.availability(roles,release,providers,bindings)

    def test_post_symbol_provider_drift_and_aggregate_work_bound_withhold_receipts(self):
        original=CLOSURE.NATIVE.SYMBOLS.availability;path=self.providers/LIBRARY;raw=path.read_bytes();calls=[]
        def changed(*args):
            result=original(*args);calls.append(True);path.chmod(0o600);path.write_bytes(raw+b'changed');path.chmod(0o400)
            return result
        with patch.object(CLOSURE.NATIVE.SYMBOLS,'availability',side_effect=changed):
            with self.assertRaises(ValueError):CLOSURE.audit(**self.arguments())
        self.assertEqual(calls,[True]);path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400)
        with patch.object(CLOSURE.NATIVE.SYMBOLS,'TOTAL_LIMIT',1):
            with self.assertRaisesRegex(ValueError,'aggregate symbol'):CLOSURE.audit(**self.arguments())

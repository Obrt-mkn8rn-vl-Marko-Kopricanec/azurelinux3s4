"""Complete inert ELF graphs, including cycles, strong/weak versions and drift."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

import test_deployment_releases as fixture
import test_native_dependencies as specimens


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_native_closure', ROOT/'Bootstrap/native_closure.py')
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)
CAPTURES = []
LIBRARY = 'libc-model.so.1'
LOADER = 'ld-model-x86-64.so.1'
INTERPRETER = '/lib64/'+LOADER
# Independent literal values for the two GNU ELF-hash test strings.
VERSIONS = (('GLIBC_2.2.5',0x09691a75,0), ('GLIBC_2.34',0x069691b4,2))


def versioned(needed, soname=None, interpreter=None, require=False, define=False):
    data=bytearray(specimens.elf(needed,soname,interpreter))+bytearray(2048)
    tags=[]
    for offset in range(512,1024,16):
        tag,value=struct.unpack_from('<qQ',data,offset)
        if tag==0:break
        tags.append((tag,value))
    size=next(value for tag,value in tags if tag==10)
    strings=bytearray(data[1024:1024+size]); labels={}
    for label,_,_ in VERSIONS:
        labels[label]=len(strings);strings.extend(label.encode()+b'\0')
    if require:
        tags.extend(((0x6ffffffe,0x400800),(0x6fffffff,1)))
        library=strings.index(LIBRARY.encode()+b'\0')
        struct.pack_into('<HHIII',data,2048,1,2,library,16,0)
        for i,(label,hashed,flags) in enumerate(VERSIONS):
            struct.pack_into('<IHHII',data,2064+16*i,hashed,flags,2+i,labels[label],16 if i==0 else 0)
    if define:
        tags.extend(((0x6ffffffc,0x400900),(0x6ffffffd,1)))
        struct.pack_into('<HHHHIII',data,2304,1,0,2,1,VERSIONS[0][1],20,0)
        struct.pack_into('<II',data,2324,labels[VERSIONS[0][0]],0)
    tags=[(tag,len(strings) if tag==10 else value) for tag,value in tags]+[(0,0)]
    dynamic=b''.join(struct.pack('<qQ',*row) for row in tags)
    data[512:512+len(dynamic)]=dynamic;data[1024:1024+len(strings)]=strings
    phcount=struct.unpack_from('<H',data,56)[0]
    for index in range(phcount):
        offset=64+56*index;kind=struct.unpack_from('<I',data,offset)[0]
        if kind in (1,2):
            length=len(data) if kind==1 else len(dynamic)
            struct.pack_into('<QQ',data,offset+32,length,length)
    return bytes(data)


class NativeClosureTests(fixture.ReleaseFixture):
    def setUp(self):
        super().setUp()
        self.app='mk8.sava'
        for row in tuple(self.documents[self.app]['files']):
            path=self.folder(self.app)/row['path']
            if not path.read_bytes().startswith(b'\x7fELF'):continue
            apphost=path.name in self.n['REL_PROGRAMS'][self.app].values()
            raw=versioned(('libcoreclr.so',LIBRARY) if apphost else (LIBRARY,),
                          None if apphost else path.name,INTERPRETER if apphost else None,require=not apphost)
            self.replace_file(row['path'],raw,self.app)
        self.providers=self.root/'native-providers';self.providers.mkdir(mode=0o700)
        self.bodies={LIBRARY:versioned((LOADER,),LIBRARY,define=True),
                     LOADER:versioned((LIBRARY,),LOADER)}
        for name,raw in self.bodies.items():
            path=self.providers/name;path.write_bytes(raw);path.chmod(0o400)
        self.plan={'schema':1,'files':[],
                   'bindings':{role:{LIBRARY:{'source':'providers','path':LIBRARY},
                                      LOADER:{'source':'providers','path':LOADER},
                                      'libcoreclr.so':{'source':'release','path':role+'/libcoreclr.so'}}
                               for role in self.n['REL_PROGRAMS'][self.app]},
                   'interpreters':{INTERPRETER:LOADER}}
        self.save()

    def save(self):
        self.plan['files']=[{'path':name,'bytes':len((self.providers/name).read_bytes()),
                            'sha256':hashlib.sha256((self.providers/name).read_bytes()).hexdigest()}
                           for name in sorted(self.bodies)]
        raw=fixture.encoded(self.plan);path=self.providers/'providers.json'
        if path.exists():path.chmod(0o600)
        path.write_bytes(raw);path.chmod(0o400);self.pin=hashlib.sha256(raw).hexdigest()

    def arguments(self):
        return dict(app=self.app,**self.value['releases'][self.app],release=self.folder(self.app),
                    providers=self.providers,providers_sha256=self.pin)

    def cli(self):
        command=[sys.executable,'-I','-B',str(ROOT/'Bootstrap/native_closure.py')]
        for name,value in self.arguments().items():command.extend(('--'+name.replace('_','-'),str(value)))
        return subprocess.run(command,capture_output=True,timeout=20)

    def change_provider(self,name,raw):
        path=self.providers/name;path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400);self.save()

    def test_complete_cli_closes_cycles_and_preserves_missing_weak_version_as_data(self):
        before=self.snapshot();child=self.cli()
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result=json.loads(child.stdout)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(set(result['provider_objects']),{LIBRARY,LOADER})
        for role in result['roles']:
            self.assertEqual(len(role['objects']),6)
            self.assertEqual(len(role['edges']),7)
            self.assertEqual(role['interpreters'][0]['provider'],LOADER)
            versions=[item for edge in role['edges'] for item in edge['versions']]
            self.assertEqual(len(versions),6)
            self.assertEqual({(item['name'],item['weak'],item['definition_present']) for item in versions},
                             {('GLIBC_2.2.5',False,True),('GLIBC_2.34',True,False)})
        self.assertEqual(self.snapshot(),before)
        CAPTURES.append(result)

    def test_missing_strong_version_wrong_hash_or_late_recursive_dependency_refuses(self):
        original=self.bodies[LIBRARY]
        for fault in ('strong','hash','recursive'):
            if fault=='strong':raw=versioned((LOADER,),LIBRARY)
            elif fault=='hash':
                changed=bytearray(original);struct.pack_into('<I',changed,2312,0x12345678);raw=bytes(changed)
            else:raw=versioned(('libabsent-model.so',),LIBRARY,define=True)
            self.change_provider(LIBRARY,raw);before=self.snapshot()
            with self.subTest(fault=fault),self.assertRaises(ValueError):CLOSURE.audit(**self.arguments())
            self.assertEqual(self.snapshot(),before)
        self.change_provider(LIBRARY,original)
        child=self.cli();self.assertEqual(child.returncode,0,child.stderr)

    def test_cross_role_unknown_or_unused_bindings_and_unsupported_dependency_mechanisms_refuse(self):
        original=copy.deepcopy(self.plan)
        for fault in ('crossrole','extra','missing','interpreter','soname'):
            self.plan=copy.deepcopy(original)
            if fault=='crossrole':self.plan['bindings']['gateway']['libcoreclr.so']['path']='application/libcoreclr.so'
            elif fault=='extra':self.plan['bindings']['gateway']['unused.so']={'source':'providers','path':LIBRARY}
            elif fault=='missing':del self.plan['bindings']['gateway'][LOADER]
            elif fault=='interpreter':self.plan['interpreters']={}
            else:self.change_provider(LOADER,versioned((LIBRARY,),'wrong-soname.so'))
            self.save()
            with self.subTest(fault=fault),self.assertRaises(ValueError):CLOSURE.audit(**self.arguments())
        self.change_provider(LOADER,self.bodies[LOADER]);self.plan=original;self.save()
        objects=CLOSURE.NATIVE.report(self.app,**self.value['releases'][self.app],path=self.folder(self.app))['objects']
        objects['gateway/libcoreclr.so']['audit']='unadmitted-audit.so'
        providers={name:CLOSURE.NATIVE.elf_declarations(raw) for name,raw in self.bodies.items()}
        with self.assertRaisesRegex(ValueError,'audit dependency'):
            CLOSURE.closure(objects,providers,self.plan,self.n['REL_PROGRAMS'][self.app])

    def test_manifest_pin_complete_tree_modes_and_aliases_refuse_without_execution(self):
        args=self.arguments();args['providers_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'explicit pin'):CLOSURE.audit(**args)
        path=self.providers/LIBRARY;path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'0400'):CLOSURE.audit(**self.arguments())
        path.chmod(0o400)
        extra=self.providers/'extra';extra.write_bytes(b'unknown')
        with self.assertRaisesRegex(ValueError,'membership'):CLOSURE.audit(**self.arguments())
        extra.unlink();alias=self.root/'outside-provider-alias';os.link(path,alias)
        with self.assertRaisesRegex(ValueError,'single-link'):CLOSURE.audit(**self.arguments())
        alias.unlink()
        raw=path.read_bytes();path.chmod(0o600);path.write_bytes(raw+b'changed');path.chmod(0o400)
        child=self.cli()
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Native provider closure refused\n'))

    def test_post_graph_provider_or_release_drift_withholds_complete_receipt(self):
        original=CLOSURE.closure
        for path in (self.providers/LIBRARY,self.folder(self.app)/'gateway/libcoreclr.so'):
            raw=path.read_bytes();mode=path.stat().st_mode&0o777;calls=[]
            def changed(*args,**kwargs):
                result=original(*args,**kwargs);calls.append(True)
                path.chmod(0o600);path.write_bytes(raw+b'changed');path.chmod(mode)
                return result
            with self.subTest(path=path.name),patch.object(CLOSURE,'closure',side_effect=changed):
                with self.assertRaises(ValueError):CLOSURE.audit(**self.arguments())
            self.assertEqual(calls,[True]);path.chmod(0o600);path.write_bytes(raw);path.chmod(mode)

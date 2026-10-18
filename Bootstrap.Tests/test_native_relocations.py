"""Owned RELA/RELR compiler DATA plus bounded faults; no object is executed."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

import test_native_symbols as fixtures


CLOSURE=fixtures.CLOSURE
CAPTURES=[]


def layout(raw):
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    loads=[];tags={};positions={}
    for index in range(header[10]):
        row=struct.unpack_from('<IIQQQQQQ',raw,header[5]+index*56)
        if row[0]==1:loads.append(row)
        if row[0]==2:
            for offset in range(row[2],row[2]+row[5],16):
                tag,value=struct.unpack_from('<qQ',raw,offset)
                if tag==0:break
                tags[tag]=value;positions[tag]=offset
    def file_offset(address):
        row=next(row for row in loads if row[3]<=address<row[3]+row[5])
        return row[2]+address-row[3]
    return tags,positions,file_offset


class NativeRelocationTests(fixtures.NativeSymbolFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass();folder=Path(cls.material.name)
        source='static int number = 7;\nint *model_pointers[4] = { &number, &number, &number, &number };\n'
        (folder/'relative.c').write_text(source)
        commands=[['/usr/bin/cc','-std=c17','-Wall','-Wextra','-Werror','-pedantic','-fPIC','-shared',
                   '-nostdlib','-Wl,--hash-style=both','-Wl,-z,pack-relative-relocs',str(folder/'relative.c'),
                   '-o',str(folder/'relative.so')],
                  ['/usr/bin/readelf','--relocs','--wide',str(folder/'relative.so'),str(folder/'consumer.so')]]
        records=[]
        for command in commands:
            child=subprocess.run(command,capture_output=True,timeout=20,cwd=folder,
                                 env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(folder)})
            records.append({'command':command,'actual_returncode':child.returncode,
                            'stdout':child.stdout.decode(),'stderr':child.stderr.decode()})
            if child.returncode:raise AssertionError(child.stderr.decode())
        cls.relative=(folder/'relative.so').read_bytes()
        if '.relr.dyn' not in records[-1]['stdout'] or 'R_X86_64_JUMP_SLOT' not in records[-1]['stdout']:
            raise AssertionError('Independent relocation fixture declaration mismatch')
        CAPTURES.append({'source':source,'commands':records,'object':{'bytes':len(cls.relative),
                         'sha256':hashlib.sha256(cls.relative).hexdigest(),'hex':cls.relative.hex()},
                         'scope':'Owned compiler/readelf DATA only; no shared object loaded or executed'})

    def test_complete_cli_binds_relocation_symbol_references_and_initial_write_ranges(self):
        before=self.snapshot();args=self.arguments();args.pop('symbols')
        command=[sys.executable,'-I','-B',str(fixtures.ROOT/'Bootstrap/native_closure.py'),'--relocations']
        for name,value in args.items():command.extend(('--'+name.replace('_','-'),str(value)))
        child=subprocess.run(command,capture_output=True,timeout=20)
        self.assertEqual((child.returncode,child.stderr),(0,b''),child.stderr)
        result=json.loads(child.stdout)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        for item in result['release_objects'].values():
            rows=item['relocations'];self.assertFalse(rows['applied'])
            self.assertEqual((rows['count'],rows['writes']),(2,2))
            self.assertEqual([(x['type'],x['symbol']) for x in rows['records']],
                             [('R_X86_64_GLOB_DAT','optional_model'),('R_X86_64_JUMP_SLOT','model_value')])
        self.assertEqual(result['provider_objects'][fixtures.LIBRARY]['relocations']['count'],0)
        self.assertEqual(self.snapshot(),before)
        CAPTURES.append({'command':command,'actual_returncode':child.returncode,
                         'stdout':child.stdout.decode(),'stderr':child.stderr.decode()})

    def test_late_rela_index_type_destination_table_and_addend_faults_refuse(self):
        tags,positions,file_offset=layout(self.consumer)
        ordinary=file_offset(tags[7]);last=file_offset(tags[23]);info=struct.unpack_from('<Q',self.consumer,last+8)[0]
        for offset,format,value in ((last+8,'<Q',(0xffffffff<<32)|7),(last+8,'<Q',(info&~0xffffffff)|5),
                (last,'<Q',0x1000),(last,'<Q',(1<<64)-4),(last+16,'<q',1),
                (last,'<Q',struct.unpack_from('<Q',self.consumer,ordinary)[0]),
                (positions[9]+8,'<Q',16),(positions[20]+8,'<Q',17),(positions[8]+8,'<Q',25)):
            raw=bytearray(self.consumer);struct.pack_into(format,raw,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(bytes(raw),True,True,True)
        raw=bytearray(self.consumer);struct.pack_into('<Q',raw,last+8,(0xffffffff<<32)|7)
        relative=next(row['path'] for row in self.documents[self.app]['files']
                      if (self.folder(self.app)/row['path']).read_bytes().startswith(b'\x7fELF'))
        self.replace_file(relative,bytes(raw),self.app);args=self.arguments();args.pop('symbols');before=self.snapshot()
        command=[sys.executable,'-I','-B',str(fixtures.ROOT/'Bootstrap/native_closure.py'),'--relocations']
        for name,value in args.items():command.extend(('--'+name.replace('_','-'),str(value)))
        child=subprocess.run(command,capture_output=True,timeout=20)
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Native provider closure refused\n'))
        self.assertEqual(self.snapshot(),before)
        CAPTURES.append({'command':command,'actual_returncode':child.returncode,
                         'stdout':child.stdout.decode(),'stderr':child.stderr.decode()})

    def test_real_packed_relative_table_and_late_bitmap_bounds_are_complete(self):
        result=CLOSURE.NATIVE.elf_declarations(self.relative,True,True,True)['relocations']
        self.assertEqual((result['count'],result['writes']),(4,4));self.assertFalse(result['applied'])
        self.assertEqual({row['table'] for row in result['records']},{'relr'})
        self.assertEqual(len({row['initial_word'] for row in result['records']}),1)
        self.assertGreater(result['records'][0]['initial_word'],0)
        tags,positions,file_offset=layout(self.relative);start=file_offset(tags[36])
        first=struct.unpack_from('<Q',self.relative,start)[0]
        for offset,value in ((start,3),(start+tags[35]-8,first),(positions[37]+8,4),
                             (positions[35]+8,tags[35]+1),(start,(1<<64)-2)):
            raw=bytearray(self.relative);struct.pack_into('<Q',raw,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(bytes(raw),True,True,True)
        with patch.object(CLOSURE.NATIVE.RELOCATIONS,'ENTRY_LIMIT',2),self.assertRaisesRegex(ValueError,'count bound'):
            CLOSURE.NATIVE.elf_declarations(self.relative,True,True,True)
        CAPTURES.append({'packed_relative_declarations':result})

    def test_typed_tls_relative_prefix_resolver_and_bss_models_refuse_bad_correspondence(self):
        parser=CLOSURE.NATIVE.RELOCATIONS
        loads=[{'address':0x1000,'offset':0,'bytes':24,'memory':0x300,'flags':6},
               {'address':0x2000,'offset':0,'bytes':24,'memory':24,'flags':5}]
        symbols=[{'name':'','type':0},{'name':'tls','type':6},{'name':'ordinary','type':1}]
        def observe(kind,index,addend=0,extra=None):
            raw=struct.pack('<QQq',0x1100,(index<<32)|kind,addend)
            tags={7:[0x1000],8:[24],9:[24]};tags.update(extra or {})
            return parser.declarations(raw,tags,lambda address,size:address-0x1000,loads,symbols)
        for kind,index in ((16,0),(16,1),(17,1),(18,1),(36,1),(8,0),(38,0)):
            with self.subTest(valid=(kind,index)):
                self.assertEqual(observe(kind,index)['writes'],1)
        self.assertEqual(observe(37,0,0x2000)['records'][0]['addend'],0x2000)
        self.assertEqual(observe(8,0,extra={0x6ffffff9:[1]})['relative_prefix_count'],1)
        for kind,index,addend,extra in ((17,2,0,None),(17,0,0,None),(1,1,0,None),
                (37,1,0x2000,None),(37,0,0x1000,None),(37,0,0x3000,None),
                (8,2,0,None),(6,2,0,{0x6ffffff9:[1]}),(8,0,0,{0x6ffffff9:[2]}),
                (8,0,0,{30:[4]}),(8,0,0,{17:[0x1000]})):
            with self.subTest(invalid=(kind,index,addend,extra)),self.assertRaises(ValueError):
                observe(kind,index,addend,extra)
        raw=struct.pack('<QQ',0x1100,3)
        result=parser.declarations(raw,{36:[0x1000],35:[16],37:[8]},lambda address,size:0,loads,symbols)
        self.assertEqual([row['initial_word'] for row in result['records']],[0,0])

    def test_optional_prior_modes_and_partial_or_unbounded_tables_remain_refusals(self):
        prior=CLOSURE.NATIVE.elf_declarations(self.consumer,True,True)
        self.assertEqual(prior,CLOSURE.NATIVE.elf_declarations(self.consumer,True,True,False))
        for flags in ((False,False,True),(True,False,True),(True,True,1)):
            with self.subTest(flags=flags),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(self.consumer,*flags)
        parser=CLOSURE.NATIVE.RELOCATIONS
        for tags in ({7:[0]},{2:[24]},{36:[0]},{7:[0],8:[0],9:[16]},
                     {7:[0],8:[24*(parser.ENTRY_LIMIT+1)],9:[24]},
                     {36:[0],35:[8*(parser.RELR_WORD_LIMIT+1)],37:[8]},
                     {7:[0,0],8:[0],9:[24]}):
            with self.subTest(tags=tags),self.assertRaises(ValueError):
                parser.declarations(b'',tags,lambda address,size:0,[],[{'name':'','type':0}])

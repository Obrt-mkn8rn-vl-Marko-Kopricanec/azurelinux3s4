"""Hash lookup metadata controls over owned compiled DATA; never load objects."""

import json
import struct
import subprocess
import sys

import test_native_symbols as fixtures


CLOSURE = fixtures.CLOSURE
CAPTURES = []


def section(raw, kind):
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    for index in range(header[12]):
        offset = header[6] + 64 * index
        row = struct.unpack_from('<IIQQQQIIQQ', raw, offset)
        if row[1] == kind:
            return offset, row
    raise AssertionError('Fixture section absent')


def without(raw, tag, kind):
    result = bytearray(raw)
    position, _ = section(raw, kind)
    struct.pack_into('<I', result, position + 4, 1)  # Uninterpreted PROGBITS DATA.
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    for index in range(header[10]):
        row = struct.unpack_from('<IIQQQQQQ', raw, header[5] + index * 56)
        if row[0] != 2:
            continue
        for offset in range(row[2], row[2] + row[5], 16):
            item, _ = struct.unpack_from('<qQ', raw, offset)
            if item == tag:
                struct.pack_into('<qQ', result, offset, 21, 0)
                return bytes(result)
    raise AssertionError('Fixture dynamic tag absent')


class NativeHashTests(fixtures.NativeSymbolFixture):
    def test_complete_cli_checks_both_hash_tables_and_all_exported_candidates(self):
        before = self.snapshot(); args = self.arguments(); args.pop('symbols')
        command = [sys.executable, '-I', '-B', str(fixtures.ROOT/'Bootstrap/native_closure.py'), '--hash-tables']
        for name, value in args.items():
            command.extend(('--'+name.replace('_', '-'), str(value)))
        child = subprocess.run(command, capture_output=True, timeout=20)
        self.assertEqual((child.returncode, child.stderr), (0, b''), child.stderr)
        result = json.loads(child.stdout)
        self.assertTrue(result['checks']['complete_sysv_gnu_hash_tables_and_export_reachability'])
        self.assertTrue(all(value is False for value in result['authority'].values()))
        for group in ('release_objects', 'provider_objects'):
            for row in result[group].values():
                tables = row['dynamic_symbols']['hash_tables']
                self.assertEqual([table['kind'] for table in tables], ['sysv', 'gnu'])
                self.assertTrue(all(table['reachable_symbols'] >= table['required_exports'] > 0 for table in tables))
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append({'command':command, 'actual_returncode':child.returncode,
                         'stdout':child.stdout.decode(), 'stderr':child.stderr.decode()})

    def test_sysv_zero_dimensions_cycle_orphan_bounds_and_missing_exports_refuse(self):
        _, row = section(self.provider, 5); offset = row[4]
        buckets, count = struct.unpack_from('<II', self.provider, offset)
        chains = offset + 8 + 4 * buckets
        symbols = CLOSURE.NATIVE.elf_declarations(self.provider, True)['dynamic_symbols']['symbols']
        exported = next(symbol['index'] for symbol in symbols if symbol['name']=='model_value')
        for position, value in ((offset,0),(offset+4,count+1),(offset+8,count),(offset+8,0),
                                (chains,1),(chains+4*exported,exported),(chains+4*(count-1),count)):
            raw = bytearray(self.provider); struct.pack_into('<I',raw,position,value)
            with self.subTest(position=position,value=value),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(bytes(raw),True,True)

    def test_gnu_complete_chains_bloom_indices_hashes_and_section_correspondence_refuse(self):
        position, row = section(self.provider,0x6ffffff6); offset = row[4]
        buckets, first, bloom_count, _ = struct.unpack_from('<IIII',self.provider,offset)
        buckets_start = offset+16+8*bloom_count; chains = buckets_start+4*buckets
        last = offset+row[5]-4
        last_hash = struct.unpack_from('<I',self.provider,last)[0]
        for address, layout, value in ((offset,'<I',0),(offset+4,'<I',0),(offset+8,'<I',3),
                (offset+12,'<I',32),(offset+16,'<Q',0),(buckets_start,'<I',0xffffffff),
                (chains,'<I',struct.unpack_from('<I',self.provider,chains)[0]^2),
                (last,'<I',last_hash&~1),(position+40,'<I',0),(position+56,'<Q',4),
                (position+32,'<Q',row[5]+4)):
            raw = bytearray(self.provider); struct.pack_into(layout,raw,address,value)
            with self.subTest(address=address,value=value),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(bytes(raw),True,True)
        # A recomputed complete provider manifest must not turn a malformed
        # bloom filter into an available strong symbol in the full command.
        raw = bytearray(self.provider);struct.pack_into('<Q',raw,offset+16,0)
        path=self.providers/fixtures.LIBRARY;path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400);self.save()
        args=self.arguments();args.pop('symbols');before=self.snapshot()
        command=[sys.executable,'-I','-B',str(fixtures.ROOT/'Bootstrap/native_closure.py'),'--hash-tables']
        for name,value in args.items():command.extend(('--'+name.replace('_','-'),str(value)))
        child=subprocess.run(command,capture_output=True,timeout=20)
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Native provider closure refused\n'))
        self.assertEqual(self.snapshot(),before)
        CAPTURES.append({'command':command,'actual_returncode':child.returncode,
                         'stdout':child.stdout.decode(),'stderr':child.stderr.decode()})

    def test_sysv_only_gnu_only_empty_gnu_and_missing_tables_are_distinct(self):
        sysv_only=without(self.provider,0x6ffffef5,0x6ffffff6)
        gnu_only=without(self.provider,4,5)
        for raw,kind in ((sysv_only,'sysv'),(gnu_only,'gnu')):
            result=CLOSURE.NATIVE.elf_declarations(raw,True,True)
            self.assertEqual([row['kind'] for row in result['dynamic_symbols']['hash_tables']],[kind])
        with self.assertRaisesRegex(ValueError,'at least one'):
            CLOSURE.NATIVE.elf_declarations(without(sysv_only,4,5),True,True)
        # No exported definitions: an empty GNU table may omit undefined rows.
        raw=struct.pack('<IIIIQI',1,1,1,0,0,0)
        table=CLOSURE.NATIVE.SYMBOLS.HASHES.gnu_table(raw,[{},{}],set())
        self.assertEqual((table['chains'],table['required_exports']),(0,0))
        with self.assertRaisesRegex(ValueError,'exported symbol'):
            CLOSURE.NATIVE.SYMBOLS.HASHES.gnu_table(raw,[{},{}],{1})

    def test_optional_behavior_and_complete_hash_bounds_remain_explicit(self):
        original=CLOSURE.NATIVE.elf_declarations(self.provider,True)
        self.assertEqual(original,CLOSURE.NATIVE.elf_declarations(self.provider,True,False))
        _,row=section(self.provider,0x6ffffff6)
        raw=bytearray(self.provider);struct.pack_into('<Q',raw,row[4]+16,0)
        self.assertEqual(CLOSURE.NATIVE.elf_declarations(bytes(raw),True),original)
        for symbols,hashes in ((False,True),(True,1),(1,False)):
            with self.subTest(flags=(symbols,hashes)),self.assertRaises(ValueError):
                CLOSURE.NATIVE.elf_declarations(self.provider,symbols,hashes)
        # Both stored table families are checked, even though a selected native
        # loader might prefer GNU and ignore a damaged legacy table.
        _,row=section(self.provider,5);raw=bytearray(self.provider);struct.pack_into('<I',raw,row[4],0)
        with self.assertRaisesRegex(ValueError,'SysV'):
            CLOSURE.NATIVE.elf_declarations(bytes(raw),True,True)

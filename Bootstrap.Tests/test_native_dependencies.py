"""Finite ELF declaration specimens; no specimen is compiled, loaded or executed."""

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_dependency_inventory', ROOT / 'Bootstrap/native_dependencies.py')
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


def elf(needed=('libc.so.6',), soname=None, interpreter=None, runpath='$ORIGIN'):
    data = bytearray(2048)
    strings = bytearray(b'\0')
    def string(value):
        offset = len(strings)
        strings.extend(value.encode('ascii') + b'\0')
        return offset
    tags = [(1, string(name)) for name in needed]
    if soname is not None:
        tags.append((14, string(soname)))
    if runpath is not None:
        tags.append((29, string(runpath)))
    tags.extend(((5, 0x400000 + 1024), (10, len(strings)), (0, 0)))
    dynamic = b''.join(struct.pack('<qQ', *tag) for tag in tags)
    headers = []
    if interpreter is not None:
        raw = interpreter.encode('ascii') + b'\0'
        data[1536:1536 + len(raw)] = raw
        headers.append((3, 4, 1536, 0x400000 + 1536, 0, len(raw), len(raw), 1))
    headers.extend(((1, 5, 0, 0x400000, 0, len(data), len(data), 4096),
                    (2, 4, 512, 0x400000 + 512, 0, len(dynamic), len(dynamic), 8),
                    (0x6474e551, 6, 0, 0, 0, 0, 0, 16)))
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 3, 62, 1, 0, 64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for index, row in enumerate(headers):
        struct.pack_into('<IIQQQQQQ', data, 64 + index * 56, *row)
    data[512:512 + len(dynamic)] = dynamic
    data[1024:1024 + len(strings)] = strings
    return bytes(data)


def versioned_elf():
    data = bytearray(elf()) + bytearray(2048)
    strings = bytearray(b'\0')
    offsets = {}
    for name in ('libc.so.6', 'libstdc++.so.6', 'libsample.so', 'GLIBC_2.2.5',
                 'GLIBC_2.34', 'GLIBCXX_3.4.26', 'DEMO_1.0', 'DEMO_0.9'):
        offsets[name] = len(strings); strings.extend(name.encode() + b'\0')
    tags = [(1, offsets['libc.so.6']), (1, offsets['libstdc++.so.6']), (14, offsets['libsample.so']),
            (5, 0x400400), (10, len(strings)), (0x6ffffffe, 0x400800), (0x6fffffff, 2),
            (0x6ffffffc, 0x400900), (0x6ffffffd, 2), (0, 0)]
    dynamic = b''.join(struct.pack('<qQ', *row) for row in tags)
    struct.pack_into('<QQ', data, 64 + 32, len(data), len(data))
    struct.pack_into('<QQ', data, 120 + 32, len(dynamic), len(dynamic))
    data[512:512 + len(dynamic)] = dynamic
    data[1024:1024 + len(strings)] = strings
    struct.pack_into('<HHIII', data, 2048, 1, 2, offsets['libc.so.6'], 16, 48)
    struct.pack_into('<IHHII', data, 2064, 0x12, 0, 2, offsets['GLIBC_2.2.5'], 16)
    struct.pack_into('<IHHII', data, 2080, 0x34, 2, 0x8003, offsets['GLIBC_2.34'], 0)
    struct.pack_into('<HHIII', data, 2096, 1, 1, offsets['libstdc++.so.6'], 16, 0)
    struct.pack_into('<IHHII', data, 2112, 0x56, 0, 4, offsets['GLIBCXX_3.4.26'], 0)
    struct.pack_into('<HHHHIII', data, 2304, 1, 1, 1, 1, 0x78, 20, 28)
    struct.pack_into('<II', data, 2324, offsets['libsample.so'], 0)
    struct.pack_into('<HHHHIII', data, 2332, 1, 0, 2, 2, 0x9a, 20, 0)
    struct.pack_into('<II', data, 2352, offsets['DEMO_1.0'], 8)
    struct.pack_into('<II', data, 2360, offsets['DEMO_0.9'], 0)
    return bytes(data)


class ElfVersionTests(unittest.TestCase):
    def test_requirements_definitions_weak_flags_and_dependency_binding_preserve_declarations(self):
        value = NATIVE.elf_declarations(versioned_elf())
        needs = value['version_requirements']
        self.assertEqual([row['library'] for row in needs], ['libc.so.6', 'libstdc++.so.6'])
        self.assertEqual([row['name'] for row in needs[0]['versions']], ['GLIBC_2.2.5', 'GLIBC_2.34'])
        self.assertEqual(needs[0]['versions'][1], {'name': 'GLIBC_2.34', 'hash': 0x34,
                         'flags': 2, 'weak': True, 'index': 3, 'hidden_index_bit': True})
        self.assertTrue(value['version_definitions'][0]['base'])
        self.assertEqual(value['version_definitions'][1]['name'], 'DEMO_1.0')
        self.assertEqual(value['version_definitions'][1]['parents'], ['DEMO_0.9'])
        rows = NATIVE.dependency_inventory({'application/app': value})
        self.assertEqual(rows[0]['version_requirements'], needs[0]['versions'])
        self.assertEqual(rows[1]['version_requirements'], needs[1]['versions'])
        self.assertTrue(all(row['loader_selection_proven'] is False for row in rows))
        self.assertEqual(NATIVE.elf_declarations(elf())['version_requirements'], [])

    def test_late_auxiliary_malformed_ranges_and_chain_counts_refuse(self):
        original = versioned_elf()
        for offset, layout, value in (
            (2048, '<H', 2), (2048 + 2, '<H', 0), (2048 + 8, '<I', 12),
            (2048 + 12, '<I', 0), (2080 + 12, '<I', 16), (2112 + 8, '<I', 0xffffffff),
            (2096 + 8, '<I', 0xfffffff0), (2332 + 6, '<H', 3),
            (2352 + 4, '<I', 4), (2360 + 4, '<I', 8),
        ):
            with self.subTest(offset=offset, value=value):
                changed = bytearray(original); struct.pack_into(layout, changed, offset, value)
                with self.assertRaises(ValueError): NATIVE.elf_declarations(bytes(changed))
        with patch.object(NATIVE.VERSIONS, 'RECORD_LIMIT', 3):
            with self.assertRaisesRegex(ValueError, 'bounded aligned'):
                NATIVE.elf_declarations(original)

    def test_missing_duplicate_excessive_or_unmapped_dynamic_table_pairs_refuse(self):
        original = versioned_elf()
        for offset, layout, value in (
            (512 + 6 * 16, '<q', 21), (512 + 8 * 16, '<q', 0x6fffffff),
            (512 + 6 * 16 + 8, '<Q', 0), (512 + 8 * 16 + 8, '<Q', 1025),
            (512 + 5 * 16 + 8, '<Q', 0x500000), (512 + 7 * 16 + 8, '<Q', 0x400901),
        ):
            with self.subTest(offset=offset, value=value):
                changed = bytearray(original); struct.pack_into(layout, changed, offset, value)
                with self.assertRaises(ValueError): NATIVE.elf_declarations(bytes(changed))


class ElfDeclarationTests(unittest.TestCase):
    def test_program_headers_and_virtual_string_mapping_preserve_order_and_search_data(self):
        result = NATIVE.elf_declarations(elf(('libsecond.so', 'libfirst.so', 'libsecond.so'),
                                              'libowned.so', '/lib64/ld-linux-x86-64.so.2'))
        self.assertEqual(result['needed'], ['libsecond.so', 'libfirst.so', 'libsecond.so'])
        self.assertEqual(result['soname'], 'libowned.so')
        self.assertEqual(result['interpreter'], '/lib64/ld-linux-x86-64.so.2')
        self.assertEqual(result['runpath'], '$ORIGIN')
        self.assertFalse(result['executable_stack_declared'])
        self.assertEqual(result['writable_executable_loads'], 0)

    def test_truncated_wrong_architecture_overflow_and_unbacked_virtual_ranges_refuse(self):
        original = elf()
        cases = [original[:63], original[:100]]
        for offset, fmt, value in ((18, '<H', 183), (32, '<Q', (1 << 64) - 1),
                                   (56, '<H', 65535), (64 + 32, '<Q', 4096),
                                   (64 + 48, '<Q', 3), (512 + 2 * 16 + 8, '<Q', 0x500000)):
            changed = bytearray(original); struct.pack_into(fmt, changed, offset, value); cases.append(bytes(changed))
        for data in cases:
            with self.subTest(header=data[:64].hex()):
                with self.assertRaises(ValueError):
                    NATIVE.elf_declarations(data)

    def test_unterminated_dynamic_table_duplicate_tags_and_bad_strings_refuse(self):
        original = elf()
        # Default tag order: NEEDED, RUNPATH, STRTAB, STRSZ, NULL.
        variants = []
        changed = bytearray(original); struct.pack_into('<qQ', changed, 512 + 4 * 16, 1, 1); variants.append(bytes(changed))
        changed = bytearray(original); struct.pack_into('<qQ', changed, 512 + 16, 5, 0x400400); variants.append(bytes(changed))
        changed = bytearray(original); struct.pack_into('<Q', changed, 512 + 8, 4096); variants.append(bytes(changed))
        changed = bytearray(original); changed[1025] = 10; variants.append(bytes(changed))
        changed = bytearray(original); changed[1024] = ord('x'); variants.append(bytes(changed))
        for data in variants:
            with self.subTest(changed=data[512:592].hex()):
                with self.assertRaises(ValueError):
                    NATIVE.elf_declarations(data)

    def test_matching_names_is_role_local_and_never_loader_resolution(self):
        objects = {'application/app': NATIVE.elf_declarations(elf(('libown.so', 'libexternal.so', '/explicit/file', '$ORIGIN/libown.so'))),
                   'application/libown.so': NATIVE.elf_declarations(elf((), 'libown.so')),
                   'gateway/libexternal.so': NATIVE.elf_declarations(elf((), 'libexternal.so'))}
        rows = NATIVE.dependency_inventory(objects)
        self.assertEqual(rows[0]['bundled_name_matches'], ['application/libown.so'])
        self.assertEqual(rows[0]['bundled_soname_matches'], ['application/libown.so'])
        for row in rows[1:]:
            self.assertEqual(row['bundled_name_matches'], [])
        self.assertTrue(all(row['loader_selection_proven'] is False for row in rows))


class NativeReleaseTests(fixture.ReleaseFixture):
    def prepare(self):
        app = 'mk8.sava'
        for row in tuple(self.documents[app]['files']):
            path = self.folder(app) / row['path']
            if path.read_bytes().startswith(b'\x7fELF'):
                leaf = path.name
                is_apphost = leaf in self.n['REL_PROGRAMS'][app].values()
                self.replace_file(row['path'], elf(('libcoreclr.so', 'libc.so.6') if is_apphost else ('libc.so.6',),
                    None if is_apphost else leaf, '/lib64/ld-linux-x86-64.so.2' if is_apphost else None), app)
        output = self.root / 'staged-native'
        staged = NATIVE.RELEASE.stage(app, '1' * 40, '2' * 40,
            {role: self.folder(app) / role for role in self.n['REL_PROGRAMS'][app]},
            {leaf: self.root / 'etc' / app / leaf for leaf in self.n['REL_CONFIGS'][app]}, output)
        return app, '1' * 40, '2' * 40, staged['declaration']['manifest_sha256'], output

    def test_complete_pinned_tree_inventory_and_cli_leave_every_byte_unchanged(self):
        args = self.prepare()
        before = self.snapshot()
        report = NATIVE.report(*args)
        self.assertEqual(len(report['objects']), 8)
        self.assertEqual(report['no_bundled_filename'], ['libc.so.6'])
        self.assertEqual(report['interpreters'], ['/lib64/ld-linux-x86-64.so.2'])
        self.assertTrue(all(value is False for value in report['authority'].values()))
        command = [sys.executable, '-B', str(ROOT / 'Bootstrap/native_dependencies.py'), '--app', args[0],
                   '--commit', args[1], '--tree', args[2], '--manifest-sha256', args[3], '--release', str(args[4])]
        child = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), report)
        self.assertEqual(self.snapshot(), before)

    def test_late_corrupt_payload_and_extra_tree_entry_cannot_yield_inventory(self):
        args = self.prepare()
        target = args[4] / 'gateway/libcoreclr.so'
        original = target.read_bytes()
        target.write_bytes(original + b'changed')
        with self.assertRaisesRegex(ValueError, 'commitment'):
            NATIVE.report(*args)
        target.write_bytes(original)
        (args[4] / 'unlisted').write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError, 'membership'):
            NATIVE.report(*args)

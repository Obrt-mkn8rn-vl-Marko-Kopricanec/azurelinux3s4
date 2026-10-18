"""Finite ELF declaration specimens; no specimen is compiled, loaded or executed."""

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

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

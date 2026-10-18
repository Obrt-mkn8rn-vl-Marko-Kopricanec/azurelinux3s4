"""Read bounded ELF64 dependency declarations from a pinned development release.

No ldd, loader, compiler, subprocess or application execution is used. Matching
names in the release does not establish the dynamic loader's selected objects.
"""

import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys


SPEC = importlib.util.spec_from_file_location('release_staging', Path(__file__).with_name('release.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
VERSION_SPEC = importlib.util.spec_from_file_location('elf_version_declarations', Path(__file__).with_name('elf_versions.py'))
VERSIONS = importlib.util.module_from_spec(VERSION_SPEC)
VERSION_SPEC.loader.exec_module(VERSIONS)
SYMBOL_SPEC = importlib.util.spec_from_file_location('elf_symbol_declarations', Path(__file__).with_name('elf_symbols.py'))
SYMBOLS = importlib.util.module_from_spec(SYMBOL_SPEC)
SYMBOL_SPEC.loader.exec_module(SYMBOLS)
ELF_LIMIT = 256 * 1024 * 1024
PROGRAM_HEADERS = 1024
DYNAMIC_ENTRIES = 8192
STRING_TABLE = 4 * 1024 * 1024
STRING_LIMIT = 4096
REPORT_LIMIT = 8 * 1024 * 1024
OBJECT_LIMIT = 512
DEPENDENCY_LIMIT = 8192
UINT64 = 1 << 64


def interval(offset, size, limit):
    if not 0 <= offset <= limit or not 0 <= size <= limit - offset:
        raise ValueError('ELF range outside its containing bytes')
    return offset, offset + size


def text_at(data, offset):
    if not 0 <= offset < len(data):
        raise ValueError('ELF string offset outside table')
    end = data.find(b'\0', offset, min(len(data), offset + STRING_LIMIT + 1))
    if end < 0 or any(byte < 32 or byte > 126 for byte in data[offset:end]):
        raise ValueError('bounded printable ELF string required')
    return data[offset:end].decode('ascii')


def elf_declarations(data, symbols=False):
    if type(symbols) is not bool:
        raise ValueError('explicit dynamic symbol inspection selection required')
    if type(data) is not bytes or not 64 <= len(data) <= ELF_LIMIT:
        raise ValueError('bounded complete ELF bytes required')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    ident, kind, machine, version, _, phoff, _, _, ehsize, phsize, phcount, _, _, _ = header
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or kind not in (2, 3) or machine != 62 or version != 1
            or ehsize != 64 or phsize != 56 or not 1 <= phcount <= PROGRAM_HEADERS or phoff < ehsize):
        raise ValueError('supported ELF64 little-endian x86-64 program headers required')
    interval(phoff, phsize * phcount, len(data))
    loads, dynamic, interpreters, stacks = [], [], [], []
    relro = False
    for index in range(phcount):
        ptype, flags, offset, address, _, size, memory, align = struct.unpack_from('<IIQQQQQQ', data, phoff + index * phsize)
        if ptype == 0:
            continue
        interval(offset, size, len(data))
        interval(address, memory, UINT64)
        if ptype == 1:
            if (size > memory or (align not in (0, 1) and (align & (align - 1) or address % align != offset % align))):
                raise ValueError('unsupported ELF load segment bounds or alignment')
            loads.append({'offset': offset, 'address': address, 'bytes': size, 'flags': flags})
        elif ptype == 2:
            dynamic.append((offset, address, size))
        elif ptype == 3:
            interpreters.append((offset, size))
        elif ptype == 0x6474e551:
            stacks.append(bool(flags & 1))
        elif ptype == 0x6474e552:
            relro = True
    if (not loads or len(dynamic) > 1 or len(interpreters) > 1 or len(stacks) > 1
            or [row['address'] for row in loads] != sorted(row['address'] for row in loads)):
        raise ValueError('complete unambiguous supported ELF segment declarations required')

    def file_offset(address, size):
        interval(address, size, UINT64)
        matches = [row['offset'] + address - row['address'] for row in loads
                   if row['address'] <= address and address + size <= row['address'] + row['bytes']]
        if len(matches) != 1:
            raise ValueError('ELF virtual range must map to one file-backed load segment')
        interval(matches[0], size, len(data))
        return matches[0]

    interpreter = None
    if interpreters:
        offset, size = interpreters[0]
        if not 2 <= size <= STRING_LIMIT:
            raise ValueError('bounded ELF interpreter required')
        raw = data[offset:offset + size]
        interpreter = text_at(raw, 0)
        if len(interpreter) + 1 != size or not interpreter.startswith('/'):
            raise ValueError('one complete absolute ELF interpreter declaration required')
    result = {'kind': 'executable' if kind == 2 else 'shared-or-pie', 'machine': 'x86_64',
              'interpreter': interpreter, 'needed': [], 'soname': None, 'rpath': None, 'runpath': None,
              'filter': None, 'auxiliary': [], 'audit': None, 'depaudit': None,
              'version_requirements': [], 'version_definitions': [],
              'executable_stack_declared': stacks[0] if stacks else None,
              'writable_executable_loads': sum(row['flags'] & 3 == 3 for row in loads),
              'relro_segment_declared': relro, 'dynamic': bool(dynamic), 'other_dynamic_tags': []}
    if not dynamic:
        if symbols:
            raise ValueError('dynamic symbol inspection requires a dynamic ELF object')
        return result
    offset, address, size = dynamic[0]
    if (not size or size % 16 or size // 16 > DYNAMIC_ENTRIES or file_offset(address, size) != offset):
        raise ValueError('bounded file-backed ELF dynamic table required')
    tags, terminated = {}, False
    for start in range(offset, offset + size, 16):
        tag, value = struct.unpack_from('<qQ', data, start)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    if not terminated:
        raise ValueError('ELF dynamic table lacks DT_NULL')
    selected = {5: 'strtab', 10: 'strsize', 14: 'soname', 15: 'rpath', 29: 'runpath',
                0x7fffffff: 'filter', 0x6ffffefc: 'audit', 0x6ffffefb: 'depaudit'}
    if any(len(tags.get(tag, [])) > 1 for tag in selected):
        raise ValueError('duplicate selected ELF dynamic tag')
    if len(tags.get(1, [])) > 512 or len(tags.get(0x7ffffffd, [])) > 512:
        raise ValueError('ELF dependency declaration count bound')
    if 5 not in tags or 10 not in tags or not 1 <= tags[10][0] <= STRING_TABLE:
        raise ValueError('complete bounded ELF dynamic string table required')
    start = file_offset(tags[5][0], tags[10][0])
    strings = data[start:start + tags[10][0]]
    if strings[:1] != b'\0' or strings[-1:] != b'\0':
        raise ValueError('ELF string table must begin and end with NUL')
    for tag, key in selected.items():
        if tag not in (5, 10) and tag in tags:
            result[key] = text_at(strings, tags[tag][0])
    result['needed'] = [text_at(strings, value) for value in tags.get(1, [])]
    result['auxiliary'] = [text_at(strings, value) for value in tags.get(0x7ffffffd, [])]
    if any(not name for name in result['needed'] + result['auxiliary']):
        raise ValueError('nonempty ELF library declarations required')
    result['version_requirements'], result['version_definitions'] = VERSIONS.declarations(
        data, tags, strings, file_offset, text_at)
    if symbols:
        result['dynamic_symbols'] = SYMBOLS.declarations(data, tags, strings, file_offset, text_at,
            result['version_requirements'], result['version_definitions'])
    result['other_dynamic_tags'] = sorted(tag for tag in tags if tag not in
        {*selected, 1, 0x7ffffffd, *VERSIONS.VERSION_TAGS, *(SYMBOLS.TAGS if symbols else ())})
    return result


def dependency_inventory(objects):
    dependencies, names, sonames, total = [], {}, {}, 0
    for path, item in objects.items():
        role = path.split('/', 1)[0]
        names.setdefault((role, path.rsplit('/', 1)[-1]), []).append(path)
        if item['soname'] is not None:
            sonames.setdefault((role, item['soname']), []).append(path)
    for name, item in sorted(objects.items()):
        role = name.split('/', 1)[0]
        for needed in item['needed']:
            if len(dependencies) >= DEPENDENCY_LIMIT:
                raise ValueError('native inventory dependency count bound')
            literal = '/' not in needed and '$' not in needed
            row = {'object': name, 'needed': needed,
                   'bundled_name_matches': sorted(names.get((role, needed), [])) if literal else [],
                   'bundled_soname_matches': sorted(sonames.get((role, needed), [])) if literal else [],
                   'version_requirements': [version for group in item['version_requirements']
                                            if group['library'] == needed for version in group['versions']],
                   'loader_selection_proven': False}
            total += len(json.dumps(row))
            if total > REPORT_LIMIT:
                raise ValueError('native inventory dependency byte bound')
            dependencies.append(row)
    return dependencies


def report(app, commit, tree, manifest_sha256, path, symbols=False):
    if type(symbols) is not bool:
        raise ValueError('explicit dynamic symbol inspection selection required')
    contract = RELEASE.contracts()
    if (app not in contract['REL_PROGRAMS']
            or any(type(value) is not str or not re.fullmatch('[0-9a-f]{40}', value) for value in (commit, tree))
            or type(manifest_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', manifest_sha256)):
        raise ValueError('explicit pinned application/source/manifest identities required')
    declaration = {'commit': commit, 'tree': tree, 'manifest_sha256': manifest_sha256}
    objects = {}
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack, RELEASE.absolute(path), links)
        before = RELEASE.inventory(root, contract)
        RELEASE.inspect_release(root, app, declaration, contract)
        raw, _ = RELEASE.read_file(root, 'release.json', contract['REL_MANIFEST_LIMIT'], capture=True)
        files, _, _, _ = contract['release_plan'](raw[2], app, declaration)
        total = 0
        for name, row in files.items():
            with RELEASE.parent_for(root, name) as (parent, leaf):
                prefix, _ = RELEASE.read_file(parent, leaf, contract['REL_FILE_LIMIT'], expected=before[name])
                if prefix[:2] != (row['bytes'], row['sha256']):
                    raise ValueError('release changed before ELF inspection')
                if not prefix[2].startswith(b'\x7fELF'):
                    continue
                if len(objects) >= OBJECT_LIMIT:
                    raise ValueError('native inventory object count bound')
                full, _ = RELEASE.read_file(parent, leaf, ELF_LIMIT, capture=True, expected=before[name])
                if full[:2] != prefix[:2]:
                    raise ValueError('ELF bytes changed before inspection')
                objects[name] = {'bytes': full[0], 'sha256': full[1], **elf_declarations(full[2], symbols)}
                total += len(json.dumps(objects[name]))
                if total > REPORT_LIMIT:
                    raise ValueError('native inventory object byte bound')
        if RELEASE.inventory(root, contract) != before:
            raise ValueError('release changed during ELF inspection')
        RELEASE.check_links(links)
    dependencies = dependency_inventory(objects)
    required_versions = {}
    for item in objects.values():
        for group in item['version_requirements']:
            required_versions.setdefault(group['library'], set()).update(row['name'] for row in group['versions'])
    result = {'scope': 'OFFLINE ELF DEPENDENCY DECLARATIONS', 'application': app, 'declaration': declaration,
            'objects': objects, 'dependencies': dependencies,
            'required_version_names': {name: sorted(versions) for name, versions in sorted(required_versions.items())},
            'no_bundled_filename': sorted({row['needed'] for row in dependencies if not row['bundled_name_matches']}),
            'interpreters': sorted({row['interpreter'] for row in objects.values() if row['interpreter']}),
            'authority': {'elf_executed': False, 'loader_resolution_proven': False, 'system_libraries_observed': False,
                          'symbol_versions_compatible': False, 'dynamic_loads_discovered': False,
                          'runtime_authenticated': False, 'application_usable': False, 'server_ready': False},
            'limits': ['DT_NEEDED, optional interpreter/search/audit/filter, and bounded GNU version requirement/definition declarations only; no relocation or symbol binding validation.',
                       'Version names, stored hashes, indices and flags are data; no provider selection, hash-algorithm authenticity, version-definition availability or per-symbol VERSYM/ABI compatibility is established. Weak requirements are retained, not promoted to mandatory failures.',
                       'Filename/SONAME matches are same-role data candidates. RPATH/RUNPATH, environment, cache, preload and loader precedence are not evaluated.',
                       'dlopen, .NET NativeLibrary/PInvoke and runtime-selected ICU/OpenSSL or provider dependencies can add requirements absent from these declarations.',
                       'Whole release verification and ELF inspection use the same held tree; observations remain sequential and do not authenticate source/build/vendor or hostile concurrent mutation.']}
    if symbols:
        result['scope'] = 'OFFLINE ELF DEPENDENCY AND DYNAMIC SYMBOL DECLARATIONS'
        result['limits'][0] = 'Complete selected dynamic symbol tables and per-symbol GNU version associations are DATA declarations; no hash lookup, relocation or symbol binding execution.'
        result['limits'][1] = 'The symbol profile requires complete matching nonextended section headers and dynamic tags. Names/types/visibility/version indices are inspected, not actual provider selection, ABI or runtime usability.'
    if len(json.dumps(result)) > REPORT_LIMIT:
        raise ValueError('complete native inventory byte bound')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'commit', 'tree', 'manifest-sha256', 'release'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--symbols', action='store_true', help='require complete section-backed dynamic symbol and VERSYM declarations')
    args = parser.parse_args(argv)
    try:
        value = report(args.app, args.commit, args.tree, args.manifest_sha256, args.release, args.symbols)
    except (OSError, ValueError, TypeError, KeyError, MemoryError, RecursionError, OverflowError, struct.error):
        print('Native dependency inventory refused', file=sys.stderr)
        return 75
    print(json.dumps(value, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

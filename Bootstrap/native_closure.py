"""Check an explicit ELF provider graph without running a loader or an object.

Caller bindings select DATA providers. They never assert the operating system's
actual loader search, per-symbol resolution, package provenance or usability.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys


SPEC = importlib.util.spec_from_file_location('closure_dependencies', Path(__file__).with_name('native_dependencies.py'))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
RELEASE = NATIVE.RELEASE
MANIFEST = 'providers.json'


def elf_hash(name):
    result = 0
    for byte in name.encode('ascii'):
        result = (result << 4) + byte
        high = result & 0xf0000000
        result ^= high >> 24
        result &= ~high
    return result


def literal(name):
    if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_+.-]{1,255}', name) or name in ('.', '..'):
        raise ValueError('literal ELF library basename required')
    return name


def version_profile(item):
    definitions = {}
    indices = set()
    for row in item['version_definitions']:
        if (row['name'] in definitions or row['index'] in indices or not 1 <= row['index'] < 0x8000
                or row['hidden_index_bit'] or row['flags'] & ~3 or elf_hash(row['name']) != row['hash']):
            raise ValueError('unique canonical GNU version definitions and hashes required')
        definitions[row['name']] = row
        indices.add(row['index'])
    for group in item['version_requirements']:
        if group['library'] not in item['needed']:
            raise ValueError('version requirement must bind a declared DT_NEEDED library')
        for row in group['versions']:
            if row['flags'] not in (0, 2) or elf_hash(row['name']) != row['hash']:
                raise ValueError('canonical GNU version requirement flags and hash required')
    return definitions


def provider_plan(raw, app, contract):
    value = contract['release_json'](raw)
    contract['deployment_fields'](value, ('schema', 'files', 'bindings', 'interpreters'))
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('explicit native provider schema required')
    rows = value['files']
    if type(rows) is not list or not 1 <= len(rows) <= NATIVE.OBJECT_LIMIT:
        raise ValueError('bounded complete provider file set required')
    files, directories, total = {}, set(), 0
    for row in rows:
        contract['deployment_fields'](row, ('path', 'bytes', 'sha256'))
        name = contract['release_relative'](row['path'])
        if (name == MANIFEST or name in files or type(row['bytes']) is not int
                or not 64 <= row['bytes'] <= NATIVE.ELF_LIMIT):
            raise ValueError('unique bounded provider file declaration required')
        contract['deployment_text'](row['sha256'], r'[0-9a-f]{64}', 64)
        total += row['bytes']
        if total > contract['REL_TOTAL_LIMIT']:
            raise ValueError('provider aggregate byte bound')
        files[name] = row
        parts = name.split('/')
        directories.update('/'.join(parts[:index]) for index in range(1, len(parts)))
    if list(files) != sorted(files) or directories & (files.keys() | {MANIFEST}):
        raise ValueError('sorted nonoverlapping provider paths required')
    contract['deployment_fields'](value['bindings'], contract['REL_PROGRAMS'][app])
    count = 0
    for role, bindings in value['bindings'].items():
        if type(bindings) is not dict:
            raise ValueError('complete per-role provider bindings required')
        count += len(bindings)
        for name, selection in bindings.items():
            literal(name)
            contract['deployment_fields'](selection, ('source', 'path'))
            contract['release_relative'](selection['path'])
            if (selection['source'] not in ('release', 'providers')
                    or selection['source'] == 'release' and not selection['path'].startswith(role + '/')
                    or selection['source'] == 'providers' and selection['path'] not in files):
                raise ValueError('provider binding must select the same release role or a complete pinned provider')
    interpreters = value['interpreters']
    if type(interpreters) is not dict or len(interpreters) > 16 or count > NATIVE.DEPENDENCY_LIMIT:
        raise ValueError('provider binding or interpreter count bound')
    for name, path in interpreters.items():
        contract['deployment_path'](name)
        if type(path) is not str or path not in files:
            raise ValueError('interpreter must select an explicit pinned provider file')
    return value, files, directories


def closure(objects, providers, plan, roles):
    # Visit each selected object once per role. Cycles are legal DATA edges and
    # cannot trigger recursive calls or unbounded reinspection.
    output, selected_providers, used_interpreters = [], set(), set()
    definitions = {('release', name): version_profile(item) for name, item in objects.items()}
    definitions.update({('providers', name): version_profile(item) for name, item in providers.items()})
    edges_total = 0
    for role in roles:
        pending = [('release', name) for name in sorted(objects) if name.startswith(role + '/')]
        if not pending:
            raise ValueError('each application role requires observed ELF objects')
        visited, edges, interpreters, used_bindings = set(), [], [], set()
        cursor = 0
        while cursor < len(pending):
            source, name = pending[cursor]; cursor += 1
            if (source, name) in visited:
                continue
            visited.add((source, name))
            if len(visited) > NATIVE.OBJECT_LIMIT * 2:
                raise ValueError('native closure object bound')
            item = (objects if source == 'release' else providers).get(name)
            if item is None:
                raise ValueError('selected provider is not a complete observed ELF object')
            if source == 'providers': selected_providers.add(name)
            if item['filter'] is not None or item['auxiliary'] or item['audit'] is not None or item['depaudit'] is not None:
                raise ValueError('ELF filter, auxiliary and audit dependency mechanisms are outside this closure profile')
            if item['interpreter'] is not None:
                interpreter = item['interpreter']; selected = plan['interpreters'].get(interpreter)
                if selected is None or providers[selected]['interpreter'] is not None:
                    raise ValueError('complete nonchained explicit ELF interpreter provider required')
                used_interpreters.add(interpreter)
                interpreters.append({'object_source': source, 'object': name,
                                     'interpreter': interpreter, 'provider': selected})
                pending.append(('providers', selected))
            for ordinal, needed in enumerate(item['needed']):
                literal(needed)
                selected = plan['bindings'][role].get(needed)
                if selected is None:
                    raise ValueError('missing explicit recursive provider binding: ' + role + '/' + needed)
                used_bindings.add(needed)
                target = (selected['source'], selected['path'])
                provider = (objects if target[0] == 'release' else providers).get(target[1])
                if (provider is None or provider['soname'] not in (None, needed)
                        or provider['soname'] is None and target[1].rsplit('/', 1)[-1] != needed):
                    raise ValueError('explicit provider SONAME or literal filename correspondence required')
                requirements = [row for group in item['version_requirements'] if group['library'] == needed
                                for row in group['versions']]
                comparisons = []
                for row in requirements:
                    definition = definitions[target].get(row['name'])
                    found = definition is not None and definition['hash'] == row['hash']
                    if not found and not row['weak']:
                        raise ValueError('missing strong declared GNU version: ' + needed + '/' + row['name'])
                    comparisons.append({'name': row['name'], 'hash': row['hash'], 'weak': row['weak'],
                                        'definition_present': found})
                edges_total += 1
                if edges_total > NATIVE.DEPENDENCY_LIMIT:
                    raise ValueError('native closure edge bound')
                edges.append({'object_source': source, 'object': name, 'ordinal': ordinal, 'needed': needed,
                              'provider': dict(selected), 'versions': comparisons})
                pending.append(target)
        if used_bindings != plan['bindings'][role].keys():
            raise ValueError('unused provider bindings are outside the exact closure')
        output.append({'role': role, 'objects': [{'source': source, 'path': name} for source, name in sorted(visited)],
                       'edges': edges, 'interpreters': interpreters})
    if selected_providers != providers.keys() or used_interpreters != plan['interpreters'].keys():
        raise ValueError('unused provider files or interpreter bindings are outside the exact closure')
    return output


def audit(app, commit, tree, manifest_sha256, release, providers, providers_sha256):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    if type(providers_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', providers_sha256):
        raise ValueError('explicit complete provider manifest SHA256 required')
    contract = RELEASE.contracts()
    original = NATIVE.report(app, commit, tree, manifest_sha256, release)
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack, RELEASE.absolute(providers), links)
        inventory = RELEASE.inventory(root, contract)
        raw, manifest_identity = RELEASE.read_file(root, MANIFEST, contract['REL_MANIFEST_LIMIT'], capture=True)
        if raw[1] != providers_sha256:
            raise ValueError('original provider manifest differs from explicit pin')
        plan, files, directories = provider_plan(raw[2], app, contract)
        expected = {'', MANIFEST} | set(files) | {name+'/' for name in directories}
        if inventory.keys() != expected:
            raise ValueError('complete exact provider tree membership required')
        for name, identity in inventory.items():
            mode = 0o700 if not name or name.endswith('/') else 0o400
            if identity[4] != os.getegid() or stat.S_IMODE(identity[2]) != mode:
                raise ValueError('private 0700 provider directories and 0400 data files required')
        objects, object_bytes = {}, 0
        for name, row in files.items():
            with RELEASE.parent_for(root, name) as (parent, leaf):
                data, identity = RELEASE.read_file(parent, leaf, NATIVE.ELF_LIMIT, capture=True, expected=inventory[name])
            if data[:2] != (row['bytes'], row['sha256']):
                raise ValueError('complete provider file commitment mismatch')
            objects[name] = {'bytes': data[0], 'sha256': data[1], 'identity': list(identity),
                             **NATIVE.elf_declarations(data[2])}
            object_bytes += len(json.dumps(objects[name]))
            if object_bytes > NATIVE.REPORT_LIMIT:
                raise ValueError('provider declaration report bound')
        selected = closure(original['objects'], objects, plan, contract['REL_PROGRAMS'][app])
        if NATIVE.report(app, commit, tree, manifest_sha256, release) != original:
            raise ValueError('complete release changed during provider comparison')
        for name, row in files.items():
            with RELEASE.parent_for(root, name) as (parent, leaf):
                data, _ = RELEASE.read_file(parent, leaf, NATIVE.ELF_LIMIT, expected=inventory[name])
            if data[:2] != (row['bytes'], row['sha256']):
                raise ValueError('provider bytes changed during closure comparison')
        final_manifest, _ = RELEASE.read_file(root, MANIFEST, contract['REL_MANIFEST_LIMIT'], capture=True,
                                               expected=manifest_identity)
        if final_manifest != raw or RELEASE.inventory(root, contract) != inventory:
            raise ValueError('complete provider tree changed during comparison')
        RELEASE.check_links(links)
        result = {'scope': 'OFFLINE EXPLICIT ELF PROVIDER DECLARATION CLOSURE', 'application': app,
                  'declaration': original['declaration'], 'providers_manifest_sha256': providers_sha256,
                  'providers_manifest_identity': list(manifest_identity), 'release_objects': original['objects'],
                  'provider_objects': objects, 'roles': selected,
                  'checks': {'all_declared_recursive_dependencies_bound': True,
                             'all_strong_declared_version_names_and_hashes_present': True,
                             'complete_original_release_and_provider_bytes_reobserved': True},
                  'authority': {'actual_loader_selection_proven': False, 'symbol_resolution_proven': False,
                                'abi_or_cpu_compatibility_proven': False, 'runtime_selected_loads_discovered': False,
                                'packages_or_build_authenticated': False, 'native_objects_executed': False,
                                'application_usable': False, 'installed': False, 'server_ready': False},
                  'limits': ['Every selected edge is an explicit caller binding, not a prediction of RPATH/RUNPATH, environment, cache, namespace, preload or actual native loader search. Those declarations remain visible in the original objects.',
                             'Strong GNU version names and canonical ELF hashes must be present in the chosen provider. Missing weak versions are reported. This intentionally refuses unversioned providers for strong requirements, although some native loaders may allow them with diagnostics.',
                             'No dynamic symbol tables, VERSYM/relocations, symbol interposition, IFUNC/CPU features, constructors or ABI implementation are validated. dlopen/.NET PInvoke/ICU/OpenSSL/provider-selected objects can lie outside DT_NEEDED.',
                             'Complete private source bytes/modes are pinned and reread, not authenticated as vendor/build/installed objects. No ldd, loader, subprocess, object/application, manager, network, GPU or host operation executes. Sequential trusted-base observations retain non-atomic/ABA/finite-IO limits.']}
    if len(json.dumps(result)) > NATIVE.REPORT_LIMIT:
        raise ValueError('native closure report bound')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'commit', 'tree', 'manifest-sha256', 'release', 'providers', 'providers-sha256'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(args.app, args.commit, args.tree, args.manifest_sha256, args.release,
                       args.providers, args.providers_sha256)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, struct.error):
        print('Native provider closure refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

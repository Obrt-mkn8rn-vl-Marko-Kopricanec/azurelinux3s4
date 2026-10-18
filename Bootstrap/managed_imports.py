"""Inspect PInvoke metadata in explicitly trusted development release outputs.

The fixed maintained .NET helper uses PEReader as a metadata API, not as a
hostile-image security validator. Input assemblies and native imports never run.
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
import subprocess
import sys


SPEC = importlib.util.spec_from_file_location('managed_import_native_tool', Path(__file__).with_name('native_tool.py'))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
RELEASE = NATIVE.RELEASE
DOTNET = '/usr/share/dotnet/dotnet'
HELPER_FILES = ('S4.ManagedImports.deps.json', 'S4.ManagedImports.dll', 'S4.ManagedImports.runtimeconfig.json')
IMAGE_LIMIT = 128 * 1024 * 1024
TOTAL_LIMIT = 256 * 1024 * 1024
IMAGE_COUNT = 512
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'DOTNET_ROOT': '/usr/share/dotnet',
               'DOTNET_EnableDiagnostics': '0', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
               'DOTNET_MULTILEVEL_LOOKUP': '0'}
AUTHORITY = ('input_assemblies_loaded', 'native_imports_called', 'native_library_resolution_proven',
             'abi_or_marshalling_compatible', 'runtime_authenticated', 'hostile_metadata_safe')


def pin(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('explicit SHA256 pin required')
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('bounded integer metadata required')
    return value


def name(value):
    if type(value) is not str or not 1 <= len(value) <= 4096 or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError('bounded printable metadata name required')
    return value


def typed_equal(left, right):
    # JSON comparison must keep booleans distinct from 0/1 and integers from
    # floating point declarations; Python container equality does not do that.
    return json.dumps(left, sort_keys=True, separators=(',', ':')) == json.dumps(right, sort_keys=True, separators=(',', ':'))


def helper_snapshot(root, contract):
    if (os.fstat(root).st_uid != os.geteuid() or stat.S_IMODE(os.fstat(root).st_mode) != 0o700
            or RELEASE.names(root, [0], 4) != sorted((*HELPER_FILES, 'helper.json'))):
        raise ValueError('complete private helper directory required')
    result = {}
    for leaf in (*HELPER_FILES, 'helper.json'):
        raw, identity = RELEASE.read_file(root, leaf, 4 * 1024 * 1024, capture=True)
        if stat.S_IMODE(identity[2]) != 0o400:
            raise ValueError('helper files require 0400')
        result[leaf] = (raw, identity)
    manifest = contract['release_json'](result['helper.json'][0][2])
    contract['deployment_fields'](manifest, ('schema', 'files'))
    if type(manifest['schema']) is not int or manifest['schema'] != 1:
        raise ValueError('helper manifest schema')
    expected = [{'path': leaf, 'bytes': result[leaf][0][0], 'sha256': result[leaf][0][1]} for leaf in HELPER_FILES]
    if not typed_equal(manifest['files'], expected):
        raise ValueError('complete exact helper byte commitments required')
    # The helper has only framework dependencies, with no caller-supplied asset
    # paths, additional frameworks, startup hooks or probing configuration.
    deps = {'runtimeTarget': {'name': '.NETCoreApp,Version=v10.0', 'signature': ''},
            'compilationOptions': {}, 'targets': {'.NETCoreApp,Version=v10.0': {
                'S4.ManagedImports/1.0.0': {'runtime': {'S4.ManagedImports.dll': {}}}}},
            'libraries': {'S4.ManagedImports/1.0.0': {'type': 'project', 'serviceable': False, 'sha512': ''}}}
    runtime = {'runtimeOptions': {'tfm': 'net10.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '10.0.0'},
               'configProperties': {'System.Reflection.Metadata.MetadataUpdater.IsSupported': False,
                                    'System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization': False}}}
    for leaf, expected_value in ((HELPER_FILES[0], deps), (HELPER_FILES[2], runtime)):
        if not typed_equal(contract['release_json'](result[leaf][0][2], False), expected_value):
            raise ValueError('fixed framework-only helper metadata required')
    return result


def frame(images):
    if not 1 <= len(images) <= IMAGE_COUNT or sum(len(raw) for raw in images) > TOTAL_LIMIT:
        raise ValueError('bounded nonempty complete managed input set required')
    result = bytearray(b'S4PINV1\n' + struct.pack('<I', len(images)))
    for index, raw in enumerate(images):
        if type(raw) is not bytes or not 64 <= len(raw) <= IMAGE_LIMIT:
            raise ValueError('complete bounded managed image required')
        result.extend(struct.pack('<IQ', index, len(raw)))
        result.extend(hashlib.sha256(raw).digest()); result.extend(raw)
    return bytes(result)


def admit_result(raw, images, contract):
    if len(raw) > NATIVE.OUTPUT_LIMIT:
        raise ValueError('managed helper output byte bound')
    result = contract['release_json'](raw)
    fields = contract['deployment_fields']
    fields(result, ('schema', 'scope', 'images', 'authority'))
    if (type(result['schema']) is not int or result['schema'] != 1
            or result['scope'] != 'MANAGED PINVOKE METADATA DECLARATIONS'
            or type(result['images']) is not list or len(result['images']) != len(images)):
        raise ValueError('complete managed helper response required')
    fields(result['authority'], AUTHORITY)
    if any(value is not False for value in result['authority'].values()):
        raise ValueError('managed helper cannot confer runtime authority')
    for index, (row, image) in enumerate(zip(result['images'], images, strict=True)):
        fields(row, ('ordinal', 'bytes', 'sha256', 'assembly_name', 'method_rows', 'implmap_rows', 'module_references', 'imports'))
        if (integer(row['ordinal'], 0, IMAGE_COUNT - 1) != index
                or integer(row['bytes'], 64, IMAGE_LIMIT) != len(image)
                or pin(row['sha256']) != hashlib.sha256(image).hexdigest()):
            raise ValueError('managed helper original-byte correspondence')
        name(row['assembly_name']); methods = integer(row['method_rows'], 0, 262144)
        maps = integer(row['implmap_rows'], 0, 16384)
        if (type(row['module_references']) is not list or len(row['module_references']) > 4096
                or type(row['imports']) is not list or len(row['imports']) != maps):
            raise ValueError('complete managed table count correspondence')
        for value in row['module_references']: name(value)
        previous = 0x06000000
        for item in row['imports']:
            fields(item, ('method_token', 'method_name', 'module', 'entry_point', 'mapping_flags',
                          'method_flags', 'implementation_flags', 'signature_bytes', 'signature_sha256'))
            token = integer(item['method_token'], previous + 1, 0x06000000 + methods); previous = token
            for field in ('method_name', 'module', 'entry_point'): name(item[field])
            flags = integer(item['mapping_flags'], 0, 65535)
            method_flags = integer(item['method_flags'], 0, 65535)
            if (item['module'] not in row['module_references'] or flags & ~0x3777
                    or flags & 0x30 == 0x30 or flags & 0x3000 == 0x3000
                    or not 0x100 <= flags & 0x700 <= 0x500 or method_flags & 0x2010 != 0x2010):
                raise ValueError('supported import method and mapping flags required')
            integer(item['implementation_flags'], 0, 65535)
            integer(item['signature_bytes'], 1, 65536); pin(item['signature_sha256'])
    return result


def audit(app, commit, tree, manifest_sha256, release, helper, helper_sha256, dotnet_sha256,
          trusted_build_outputs=False):
    if trusted_build_outputs is not True or os.geteuid() == 0:
        raise ValueError('explicit trusted build outputs and unprivileged developer required')
    contract = RELEASE.contracts()
    if app not in contract['REL_PROGRAMS'] or any(type(x) is not str or not re.fullmatch('[0-9a-f]{40}', x) for x in (commit, tree)):
        raise ValueError('exact application/source identities required')
    declaration = {'commit': commit, 'tree': tree, 'manifest_sha256': pin(manifest_sha256)}
    pin(helper_sha256); pin(dotnet_sha256)
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack, RELEASE.absolute(release), links)
        before = RELEASE.inventory(root, contract)
        RELEASE.inspect_release(root, app, declaration, contract)
        manifest, _ = RELEASE.read_file(root, 'release.json', contract['REL_MANIFEST_LIMIT'], capture=True)
        files, _, _, _ = contract['release_plan'](manifest[2], app, declaration)
        images, by_digest, paths = [], {}, []
        for path, entry in files.items():
            with RELEASE.parent_for(root, path) as (parent, leaf):
                prefix, _ = RELEASE.read_file(parent, leaf, contract['REL_FILE_LIMIT'], expected=before[path])
                if prefix[:2] != (entry['bytes'], entry['sha256']):
                    raise ValueError('release changed before managed inspection')
                if not path.endswith('.dll'):
                    continue
                if not prefix[2].startswith(b'MZ'):
                    raise ValueError('managed DLL metadata profile required')
                full, _ = RELEASE.read_file(parent, leaf, IMAGE_LIMIT, capture=True, expected=before[path])
                if full[:2] != prefix[:2]: raise ValueError('managed image changed during capture')
                if full[1] not in by_digest:
                    by_digest[full[1]] = len(images); images.append(full[2])
                    if len(images) > IMAGE_COUNT or sum(len(raw) for raw in images) > TOTAL_LIMIT:
                        raise ValueError('managed unique image bound')
                elif images[by_digest[full[1]]] != full[2]:
                    raise ValueError('managed digest collision')
                paths.append({'path': path, 'ordinal': by_digest[full[1]], 'bytes': full[0], 'sha256': full[1]})
        framed = frame(images)
        helper_root = RELEASE.anchor(stack, RELEASE.absolute(helper), links)
        helper_before = helper_snapshot(helper_root, contract)
        if helper_before['helper.json'][0][1] != helper_sha256:
            raise ValueError('helper manifest pin mismatch')
        tool = NATIVE.PinnedExecutable(stack, dotnet_sha256, path=DOTNET, label='managed metadata runtime',
                                      environment=ENVIRONMENT, timeout=30)
        prefix = '/proc/self/fd/' + str(helper_root) + '/'
        raw = tool.run(['exec', '--runtimeconfig', prefix + HELPER_FILES[2], '--depsfile', prefix + HELPER_FILES[0],
                        prefix + HELPER_FILES[1]], raw=framed, descriptors=(helper_root,))
        result = admit_result(raw, images, contract)
        if helper_snapshot(helper_root, contract) != helper_before:
            raise ValueError('helper changed during managed inspection')
        RELEASE.inspect_release(root, app, declaration, contract)
        if RELEASE.inventory(root, contract) != before:
            raise ValueError('release changed during managed inspection')
        RELEASE.check_links(links); tool.check()
        runtime = {'sha256': dotnet_sha256, 'identity': RELEASE.identity(tool.before), 'commands': tool.commands}
    return {'scope': 'TRUSTED DEVELOPMENT MANAGED IMPORT DECLARATIONS', 'application': app,
            'declaration': declaration, 'files': paths, 'metadata': result, 'runtime': runtime,
            'helper_manifest_sha256': helper_sha256,
            'authority': {**dict.fromkeys(AUTHORITY, False), 'source_or_build_authenticated': False,
                          'all_dynamic_loads_discovered': False, 'application_usable': False, 'server_ready': False},
            'limits': ['PEReader is documented for trusted images only. Framing and table bounds are not hostile-input containment or native memory-safety/progress guarantees.',
                       'Complete selected ImplMap/PInvoke rows and signature hashes are metadata. Signatures, marshaling, custom attributes, LibraryImport generation, NativeLibrary.Load and resolver callbacks are not evaluated.',
                       'Module and entry-point names do not select Linux libraries or establish symbol availability, ABI, privilege, loader search, runtime or application usability.',
                       'The explicitly pinned maintained helper executes on the trusted local framework; only input assembly bytes remain inert. Host pin and helper hashes do not authenticate framework/build/vendor or prevent concurrent mutation.',
                       'Whole release, private helper and held ancestry observations are sequential and non-atomic. This tool installs or starts no application/service.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('app', 'commit', 'tree', 'manifest-sha256', 'release', 'helper', 'helper-sha256', 'dotnet-sha256'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--trusted-build-outputs', action='store_true', help='required: PEReader is for trusted development images only')
    args = parser.parse_args(argv)
    try:
        result = audit(**vars(args))
    except (OSError, ValueError, TypeError, KeyError, MemoryError, RecursionError, OverflowError, subprocess.SubprocessError):
        print('Managed import inventory refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Observe complete protected self-contained releases; do not execute their bytes."""

import struct as rel_struct
import math as rel_math


REL_MANIFEST_LIMIT = 4 * 1024 * 1024
REL_FILE_LIMIT = 256 * 1024 * 1024
REL_TOTAL_LIMIT = 2 * 1024 * 1024 * 1024
REL_FILES = 4096
REL_ENTRIES = 8192
REL_DEP_REFERENCES = 8192
REL_PROGRAMS = {
    'mk8.sava': {'application': 'Mk8.Sava.Application', 'gateway': 'Mk8.Sava.Gateway'},
    'mk8.drava': {'application': 'mk8.drava.Application', 'gateway': 'mk8.drava.Gateway'},
    'mk8.dns': {'application': 'mk8.dns.Application', 'gateway': 'mk8.dns.Gateway'},
    'mk8.email': {'worker': 'mk8.email.Application.Worker', 'gateway': 'mk8.email.Gateway'},
}
REL_CONFIGS = {
    'mk8.sava': ('policy.env', 'application.env', 'gateway.env', 'rpc.key'),
    'mk8.drava': ('application.json', 'gateway.json'),
    'mk8.dns': ('control-plane.json', 'authority.json'),
    'mk8.email': ('gateway.json', 'worker.json'),
}


def release_relative(value):
    deployment_path('/' + value if type(value) is str else value)
    return value


def release_float(value):
    number = float(value)
    if not rel_math.isfinite(number):
        raise ValueError('nonfinite release number')
    return number


def release_json(data, final_lf=True):
    if (not data or len(data) > REL_MANIFEST_LIMIT or (final_lf and not data.endswith(b'\n'))
            or any(byte < 32 and byte != 10 or byte > 126 for byte in data)):
        raise ValueError('bounded ASCII/LF release JSON required')
    return dep_json.loads(data, object_pairs_hook=deployment_object, parse_float=release_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite release number')))


def release_plan(data, app, declaration):
    if dep_hash.sha256(data).hexdigest() != declaration['manifest_sha256']:
        raise ValueError('release manifest digest mismatch')
    value = release_json(data)
    deployment_fields(value, ('schema', 'app', 'commit', 'tree', 'profile', 'files', 'configuration'))
    if (type(value['schema']) is not int or value['schema'] != 1 or value['app'] != app
            or value['commit'] != declaration['commit'] or value['tree'] != declaration['tree']
            or value['profile'] != 'self-contained-net10-linux-x64'):
        raise ValueError('release declaration correspondence')
    rows = value['files']
    if type(rows) is not list or not 1 <= len(rows) <= REL_FILES:
        raise ValueError('release file count bound')
    files, total = {}, 0
    for row in rows:
        deployment_fields(row, ('path', 'bytes', 'sha256', 'mode'))
        name = release_relative(row['path'])
        if (name == 'release.json' or name in files or type(row['bytes']) is not int
                or not 0 <= row['bytes'] <= REL_FILE_LIMIT or row['mode'] not in ('0644', '0755')):
            raise ValueError('release file identity/type/bound')
        deployment_text(row['sha256'], r'[0-9a-f]{64}', 64)
        total += row['bytes']
        if total > REL_TOTAL_LIMIT:
            raise ValueError('release aggregate byte bound')
        files[name] = dict(row)
    if list(files) != sorted(files):
        raise ValueError('release files must be unique and sorted')
    directories = set()
    for name in files:
        parts = name.split('/')
        directories.update('/'.join(parts[:index]) for index in range(1, len(parts)))
        if parts[0] not in REL_PROGRAMS[app] or len(parts) < 2:
            raise ValueError('release role directory required')
    if directories & files.keys() or len(directories) + len(files) + 1 > REL_ENTRIES:
        raise ValueError('release path prefix or entry bound')
    for role, program in REL_PROGRAMS[app].items():
        for suffix in ('', '.dll', '.deps.json', '.runtimeconfig.json'):
            name = role + '/' + program + suffix
            if name not in files or files[name]['mode'] != ('0755' if not suffix else '0644') or not files[name]['bytes']:
                raise ValueError('complete role entry required')
        for leaf in ('libhostfxr.so', 'libhostpolicy.so', 'libcoreclr.so', 'System.Private.CoreLib.dll'):
            if role + '/' + leaf not in files or not files[role + '/' + leaf]['bytes']:
                raise ValueError('self-contained runtime files required')
    deployment_fields(value['configuration'], REL_CONFIGS[app])
    for digest in value['configuration'].values():
        deployment_text(digest, r'[0-9a-f]{64}', 64)
    return files, directories, total, value['configuration']


def release_directory(info):
    if (not dep_stat.S_ISDIR(info.st_mode) or info.st_uid != DEP_TRUSTED_UID
            or info.st_gid != DEP_TRUSTED_UID or dep_stat.S_IMODE(info.st_mode) != 0o755):
        raise ValueError('release requires protected root-owned 0755 directories')


def release_file(parent, name, limit, mode, expected=None, capture=False):
    def admit(info):
        if (not dep_stat.S_ISREG(info.st_mode) or info.st_uid != DEP_TRUSTED_UID
                or info.st_gid != DEP_TRUSTED_UID or info.st_nlink != 1
                or dep_stat.S_IMODE(info.st_mode) != mode or not 0 <= info.st_size <= limit):
            raise ValueError('unprotected or oversized release file')
        if expected is not None and info.st_size != expected['bytes']:
            raise ValueError('release file length mismatch')
    before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
    admit(before)
    with dep_context.ExitStack() as stack:
        fd = dep_os.open(name, DEP_OPEN, dir_fd=parent)
        stack.callback(dep_os.close, fd)
        initial = dep_os.fstat(fd)
        admit(initial)
        if deployment_identity(before) != deployment_identity(initial):
            raise ValueError('release file changed on open')
        results = []
        for _ in range(2):
            dep_os.lseek(fd, 0, dep_os.SEEK_SET)
            digest, size, kept = dep_hash.sha256(), 0, bytearray()
            while True:
                chunk = dep_os.read(fd, min(128 * 1024, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError('actual release EOF bound')
                digest.update(chunk)
                kept.extend(chunk if capture else chunk[:max(0, 64 - len(kept))])
            results.append((size, digest.hexdigest(), bytes(kept)))
        if results[0] != results[1] or results[0][0] != initial.st_size:
            raise ValueError('release byte readback mismatch')
        if expected is not None and results[0][1] != expected['sha256']:
            raise ValueError('release content digest mismatch')
        for info in (dep_os.fstat(fd), dep_os.stat(name, dir_fd=parent, follow_symlinks=False)):
            admit(info)
            if deployment_identity(info) != deployment_identity(initial):
                raise ValueError('release held/path metadata changed')
    return results[0], initial


def release_entries(fd, budget):
    names = []
    with dep_os.scandir(fd) as entries:
        for entry in entries:
            budget[0] += 1
            if budget[0] > REL_ENTRIES * 2:
                raise ValueError('release scan entry bound')
            release_relative(entry.name)
            if '/' in entry.name or entry.name in names:
                raise ValueError('release directory entry identity')
            names.append(entry.name)
    return sorted(names)


def release_elf(data, executable):
    if (len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01'
            or rel_struct.unpack_from('<H', data, 18)[0] != 62
            or rel_struct.unpack_from('<H', data, 16)[0] not in ((2, 3) if executable else (3,))
            or rel_struct.unpack_from('<I', data, 20)[0] != 1):
        raise ValueError('unsupported declared linux-x64 ELF header')


def release_runtime(app, files, observed):
    summaries = []
    for role, program in REL_PROGRAMS[app].items():
        prefix = role + '/'
        release_elf(observed[prefix + program][2], True)
        for name, result in observed.items():
            if name.startswith(prefix) and dep_re.search(r'\.so(?:\.[0-9]+)*$', name):
                release_elf(result[2], False)
        # SDK writers emit complete JSON texts without a terminal LF. Preserve
        # their exact admitted bytes; human manifests/configurations keep LF.
        runtime = release_json(observed[prefix + program + '.runtimeconfig.json'][2], final_lf=False)
        deployment_fields(runtime, ('runtimeOptions',))
        options = runtime['runtimeOptions']
        if (type(options) is not dict or not {'tfm', 'includedFrameworks'} <= options.keys()
                or options.keys() - {'tfm', 'includedFrameworks', 'configProperties'} or options['tfm'] != 'net10.0'
                or type(options.get('configProperties', {})) is not dict):
            raise ValueError('self-contained net10 runtime options required')
        frameworks = options['includedFrameworks']
        if type(frameworks) is not list or not 1 <= len(frameworks) <= 2:
            raise ValueError('runtime framework declarations')
        names = []
        for framework in frameworks:
            deployment_fields(framework, ('name', 'version'))
            if framework['name'] in names or framework['name'] not in ('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'):
                raise ValueError('unsupported or duplicate included framework')
            deployment_text(framework['version'], r'10\.0\.(?:0|[1-9][0-9]{0,4})', 16)
            names.append(framework['name'])
        if set(names) != ({'Microsoft.NETCore.App'} if role == 'worker' else {'Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'}):
            raise ValueError('complete role frameworks required')
        deps = release_json(observed[prefix + program + '.deps.json'][2], final_lf=False)
        target = '.NETCoreApp,Version=v10.0/linux-x64'
        if (type(deps) is not dict or not {'runtimeTarget', 'targets', 'libraries'} <= deps.keys()
                or deps.keys() - {'runtimeTarget', 'compilationOptions', 'targets', 'libraries'}
                or type(deps['runtimeTarget']) is not dict or deps['runtimeTarget'].get('name') != target
                or deps['runtimeTarget'].keys() - {'name', 'signature'}
                or type(deps['targets']) is not dict or set(deps['targets']) != {target}
                or type(deps['libraries']) is not dict or type(deps['targets'][target]) is not dict
                or set(deps['targets'][target]) != set(deps['libraries']) or not 1 <= len(deps['libraries']) <= REL_FILES):
            raise ValueError('linux-x64 dependency target required')
        assets, references = set(), 0
        for library, groups in deps['targets'][target].items():
            if (type(groups) is not dict or groups.keys() - {'dependencies', 'runtime', 'native', 'resources', 'runtimeTargets'}
                    or type(deps['libraries'][library]) is not dict):
                raise ValueError('dependency library correspondence')
            dependencies = groups.get('dependencies', {})
            if type(dependencies) is not dict:
                raise ValueError('typed dependency edges required')
            for name, version in dependencies.items():
                if type(version) is not str or name + '/' + version not in deps['libraries']:
                    raise ValueError('dependency edge outside release target')
            for kind in ('runtime', 'native', 'resources', 'runtimeTargets'):
                group = groups.get(kind, {})
                if type(group) is not dict:
                    raise ValueError('typed dependency asset group required')
                references += len(group)
                if references > REL_DEP_REFERENCES:
                    raise ValueError('dependency asset reference bound')
                for asset, metadata in group.items():
                    release_relative(asset)
                    if type(metadata) is not dict:
                        raise ValueError('typed dependency asset metadata required')
                    if kind == 'runtimeTargets' and (metadata.get('rid') != 'linux-x64' or metadata.get('assetType') not in ('runtime', 'native')):
                        raise ValueError('unsupported runtime target asset')
                    # RID publishes may flatten runtime/native package paths.
                    candidates = {prefix + asset}
                    if kind != 'resources':
                        candidates.add(prefix + asset.rsplit('/', 1)[-1])
                    actual = candidates & files.keys()
                    if len(actual) != 1:
                        raise ValueError('dependency asset absent or ambiguous in release')
                    assets.update(actual)
        if prefix + program + '.dll' not in assets or prefix + 'System.Private.CoreLib.dll' not in assets:
            raise ValueError('application/core runtime dependency rows required')
        summaries.append({'role': role, 'program': program, 'frameworks': frameworks,
                          'dependency_files': len(assets), 'runtime_target': target})
    return summaries


def release_observe(app, declaration):
    path = '/opt/' + app + '/releases/' + declaration['commit']
    parts = deployment_path(path)
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('release observation requires root')
    with dep_context.ExitStack() as stack:
        root = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
        stack.callback(dep_os.close, root)
        initial_root = dep_os.fstat(root)
        deployment_directory(initial_root)
        held, links, leaves = [(root, initial_root)], [], []
        parent = root
        for name in parts:
            before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
            release_directory(before)
            child = dep_os.open(name, DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=parent)
            stack.callback(dep_os.close, child)
            current = dep_os.fstat(child)
            release_directory(current)
            if deployment_identity(current) != deployment_identity(before):
                raise ValueError('release ancestry changed on open')
            links.append((parent, name, before)); held.append((child, current)); parent = child
        result, info = release_file(parent, 'release.json', REL_MANIFEST_LIMIT, 0o400, capture=True)
        leaves.append((parent, 'release.json', info))
        files, directories, total, configuration = release_plan(result[2], app, declaration)
        observed, observed_identities, budget = {}, {}, [0]
        directory_identity = list(deployment_identity(held[-1][1]))

        def walk(fd, prefix):
            names = release_entries(fd, budget)
            expected = {name[len(prefix):].split('/', 1)[0] for name in files if name.startswith(prefix)}
            if not prefix:
                expected.add('release.json')
            if set(names) != expected:
                raise ValueError('complete release tree membership mismatch')
            for leaf in names:
                name = prefix + leaf
                if name == 'release.json':
                    continue
                if name in directories:
                    before = dep_os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                    release_directory(before)
                    if before.st_dev != info.st_dev:
                        raise ValueError('cross-device release directory')
                    child = dep_os.open(leaf, DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=fd)
                    stack.callback(dep_os.close, child)
                    current = dep_os.fstat(child)
                    if deployment_identity(current) != deployment_identity(before):
                        raise ValueError('release directory changed on open')
                    held.append((child, current)); links.append((fd, leaf, before))
                    walk(child, name + '/')
                else:
                    json_file = name in {role + '/' + program + suffix
                                         for role, program in REL_PROGRAMS[app].items()
                                         for suffix in ('.deps.json', '.runtimeconfig.json')}
                    limit = REL_MANIFEST_LIMIT if json_file else REL_FILE_LIMIT
                    value, current = release_file(fd, leaf, limit, int(files[name]['mode'], 8), files[name], json_file)
                    if current.st_dev != info.st_dev:
                        raise ValueError('cross-device release file')
                    observed[name] = value; leaves.append((fd, leaf, current))
                    observed_identities[name] = list(deployment_identity(current))
            if release_entries(fd, budget) != names:
                raise ValueError('release directory scan changed')

        walk(parent, '')
        if set(observed) != files.keys():
            raise ValueError('incomplete observed release')
        runtime = release_runtime(app, files, observed)
        for fd, previous in held:
            if deployment_identity(dep_os.fstat(fd)) != deployment_identity(previous):
                raise ValueError('release held directory changed')
        for fd, name, previous in links + leaves:
            if deployment_identity(dep_os.stat(name, dir_fd=fd, follow_symlinks=False)) != deployment_identity(previous):
                raise ValueError('release path changed')
        fresh = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
        stack.callback(dep_os.close, fresh)
        if deployment_identity(dep_os.fstat(fresh)) != deployment_identity(initial_root):
            raise ValueError('release root changed')
    return {'app': app, 'directory': path, 'declaration': dict(declaration), 'files': list(files.values()),
            'directory_identity': directory_identity, 'manifest_identity': list(deployment_identity(info)),
            'observed_files': [{'path': name, 'identity': observed_identities[name]} for name in sorted(files)],
            'file_count': len(files), 'payload_bytes': total, 'runtime': runtime, 'configuration': configuration,
            'manifest_bytes': result[0], 'manifest_sha256': result[1],
            'complete_tree_observed': True, 'two_file_hash_passes': True, 'checked_closes_completed': True}

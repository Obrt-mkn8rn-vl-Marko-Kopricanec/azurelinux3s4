"""Stage explicit SDK publishes as an offline development release, without running them.

The output is a new directory below an existing private developer directory.
Configuration contents stay in their original files; only their hashes enter the
manifest. This tool neither builds nor installs, signs, loads or starts an app.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CHUNK = 128 * 1024


def contracts():
    # Fixed maintained modules, not a caller-selected importer or plugin. Their
    # top levels define contracts only; no dispatcher or protected host IO runs.
    namespace = {"__name__": "development_release_contracts"}
    for name in ("configuration", "policy", "releases"):
        path = ROOT / "Deployment" / (name + ".py")
        exec(compile(path.read_bytes(), str(path), "exec"), namespace)
    return namespace


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def base(info):
    return identity(info)[:5]


def absolute(value):
    value = os.fspath(value)
    if (not os.path.isabs(value) or os.path.normpath(value) != value
            or len(value) > 4096 or any(part in (".", "..", "") for part in value[1:].split("/"))):
        raise ValueError("explicit canonical absolute development path required")
    return value


def anchor(stack, path, links):
    """Open every directory component without following links, retaining ancestry."""
    fd = os.open("/", READ | os.O_DIRECTORY)
    stack.callback(os.close, fd)
    for name in absolute(path)[1:].split("/"):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        child = os.open(name, READ | os.O_DIRECTORY, dir_fd=fd)
        stack.callback(os.close, child)
        if identity(os.fstat(child)) != identity(before):
            raise ValueError("development directory changed during open")
        links.append((fd, name, child, base(before)))
        fd = child
    return fd


def check_links(links):
    for parent, name, child, expected in links:
        if (base(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected
                or base(os.fstat(child)) != expected):
            raise ValueError("development input or output ancestry changed")


def names(fd, budget, limit):
    result = []
    with os.scandir(fd) as entries:
        for entry in entries:
            budget[0] += 1
            if budget[0] > limit:
                raise ValueError("publish entry count bound")
            result.append(entry.name)
    return sorted(result)


def regular(info, limit):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o7000 or not 0 <= info.st_size <= limit):
        raise ValueError("bounded developer-owned single-link regular file required")


def read_file(parent, leaf, limit, capture=False, writer=None, expected=None):
    before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    regular(before, limit)
    if expected is not None and identity(before) != expected:
        raise ValueError("publish input changed since admission")
    fd = os.open(leaf, READ, dir_fd=parent)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError("publish file changed during open")
        passes = []
        for index in range(2):
            os.lseek(fd, 0, os.SEEK_SET)
            digest, size, kept = hashlib.sha256(), 0, bytearray()
            while True:
                chunk = os.read(fd, min(CHUNK, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError("publish EOF byte bound")
                digest.update(chunk)
                kept.extend(chunk if capture else chunk[:max(0, 64 - len(kept))])
                if writer is not None and index == 0:
                    write_all(writer, chunk)
            passes.append((size, digest.hexdigest(), bytes(kept)))
        if passes[0] != passes[1] or passes[0][0] != before.st_size:
            raise ValueError("publish file bytes changed during read")
        if (identity(os.fstat(fd)) != identity(before)
                or identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != identity(before)):
            raise ValueError("publish file identity changed during read")
    finally:
        os.close(fd)
    return passes[0], identity(before)


def inventory(fd, contract):
    entries, budget = {}, [0]
    device = os.fstat(fd).st_dev

    def walk(current, prefix):
        before = os.fstat(current)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_dev != device or before.st_mode & 0o7000):
            raise ValueError("ordinary same-device developer publish directory required")
        entries[prefix] = identity(before)
        listed = names(current, budget, contract['REL_ENTRIES'])
        for leaf in listed:
            name = prefix + leaf
            contract['release_relative'](name)
            info = os.stat(leaf, dir_fd=current, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(leaf, READ | os.O_DIRECTORY, dir_fd=current)
                try:
                    if identity(os.fstat(child)) != identity(info):
                        raise ValueError("publish directory changed during scan")
                    walk(child, name + '/')
                finally:
                    os.close(child)
            else:
                regular(info, contract['REL_FILE_LIMIT'])
                if info.st_dev != device:
                    raise ValueError("cross-device publish file")
                entries[name] = identity(info)
        if identity(os.fstat(current)) != identity(before):
            raise ValueError("publish directory changed during scan")

    walk(fd, '')
    return entries


@contextlib.contextmanager
def parent_for(root, name):
    with contextlib.ExitStack() as stack:
        parent = root
        parts = name.split('/')
        for leaf in parts[:-1]:
            parent = os.open(leaf, READ | os.O_DIRECTORY, dir_fd=parent)
            stack.callback(os.close, parent)
        yield parent, parts[-1]


def write_all(fd, data):
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if type(count) is not int or not 0 < count <= len(data) - offset:
            raise ValueError("incomplete development release write")
        offset += count


def create_file(parent, leaf):
    return os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)


def inspect_release(root, app, declaration, contract):
    before = inventory(root, contract)
    manifest, _ = read_file(root, 'release.json', contract['REL_MANIFEST_LIMIT'], capture=True)
    files, directories, total, _ = contract['release_plan'](manifest[2], app, declaration)
    expected = {'', 'release.json'} | set(files) | {name + '/' for name in directories}
    if before.keys() != expected:
        raise ValueError("complete staged release membership mismatch")
    for name, info in before.items():
        mode = 0o755 if not name or name.endswith('/') else 0o400 if name == 'release.json' else int(files[name]['mode'], 8)
        if stat.S_IMODE(info[2]) != mode:
            raise ValueError("staged release mode mismatch")
    observed = {}
    for name, row in files.items():
        role, relative = name.split('/', 1)
        program = contract['REL_PROGRAMS'][app][role]
        capture = relative in (program + '.deps.json', program + '.runtimeconfig.json')
        limit = contract['REL_MANIFEST_LIMIT'] if capture else contract['REL_FILE_LIMIT']
        with parent_for(root, name) as (parent, leaf):
            value, _ = read_file(parent, leaf, limit, capture, expected=before[name])
        if value[:2] != (row['bytes'], row['sha256']):
            raise ValueError("staged release payload commitment mismatch")
        observed[name] = value
    runtime = contract['release_runtime'](app, files, observed)
    if inventory(root, contract) != before:
        raise ValueError("staged release changed during verification")
    return {'files': len(files), 'payload_bytes': total, 'runtime': runtime}


def verify(app, commit, tree, manifest_sha256, path):
    contract = contracts()
    if (app not in contract['REL_PROGRAMS']
            or any(type(value) is not str or not re.fullmatch('[0-9a-f]{40}', value) for value in (commit, tree))
            or type(manifest_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', manifest_sha256)):
        raise ValueError("exact application, source and manifest commitments required")
    declaration = {'commit': commit, 'tree': tree, 'manifest_sha256': manifest_sha256}
    with contextlib.ExitStack() as stack:
        links = []
        root = anchor(stack, absolute(path), links)
        observed = inspect_release(root, app, declaration, contract)
        check_links(links)
    return {'scope': 'OFFLINE DEVELOPMENT RELEASE VERIFICATION', 'application': app,
            'declaration': declaration, **observed, 'source_or_build_authenticated': False,
            'installed_ownership_admitted': False, 'application_executed': False, 'server_ready': False}


def stage(app, commit, tree, roles, configuration, output):
    if os.geteuid() == 0:
        raise ValueError("run release staging as an unprivileged developer")
    contract = contracts()
    if app not in contract['REL_PROGRAMS'] or type(roles) is not dict or type(configuration) is not dict:
        raise ValueError("explicit supported application and inputs required")
    if (roles.keys() != contract['REL_PROGRAMS'][app].keys()
            or configuration.keys() != set(contract['REL_CONFIGS'][app])):
        raise ValueError("complete exact role and configuration input sets required")
    if any(type(value) is not str or not re.fullmatch('[0-9a-f]{40}', value) for value in (commit, tree)):
        raise ValueError("explicit lowercase Git commit and tree declarations required")
    output = absolute(output)
    roles = {role: absolute(path) for role, path in roles.items()}
    configuration = {name: absolute(path) for name, path in configuration.items()}
    if len(set(roles.values())) != len(roles) or len(set(configuration.values())) != len(configuration):
        raise ValueError("distinct role directories and configuration inputs required")
    if any(first.startswith(second + '/') for first in roles.values() for second in roles.values() if first != second):
        raise ValueError("publish role directories must not overlap")
    for source in roles.values():
        if output == source or output.startswith(source + '/') or source.startswith(output + '/'):
            raise ValueError("output must be separate from publish inputs")
    if any(path == output or path.startswith(output + '/') for path in configuration.values()):
        raise ValueError("output must be separate from configuration inputs")
    with contextlib.ExitStack() as stack:
        links, roots, inventories, observed, rows, configs = [], {}, {}, {}, [], {}
        target_parent = anchor(stack, os.path.dirname(output), links)
        parent_info = os.fstat(target_parent)
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise ValueError("output parent must be an existing developer-owned 0700 directory")
        output_leaf = os.path.basename(output)
        try:
            os.stat(output_leaf, dir_fd=target_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("development release output already exists")
        total = 0
        for role, path in roles.items():
            root = roots[role] = anchor(stack, path, links)
            inventories[role] = inventory(root, contract)
            program = contract['REL_PROGRAMS'][app][role]
            for name, original in sorted(inventories[role].items()):
                if not name or name.endswith('/'):
                    continue
                capture = name in (program + '.deps.json', program + '.runtimeconfig.json')
                limit = contract['REL_MANIFEST_LIMIT'] if capture else contract['REL_FILE_LIMIT']
                with parent_for(root, name) as (parent, leaf):
                    value, _ = read_file(parent, leaf, limit, capture, expected=original)
                total += value[0]
                if total > contract['REL_TOTAL_LIMIT'] or len(rows) >= contract['REL_FILES']:
                    raise ValueError("complete publish count or byte bound")
                full = role + '/' + name
                observed[full] = value
                rows.append({'path': full, 'bytes': value[0], 'sha256': value[1],
                             'mode': '0755' if name == program else '0644'})
        for name, path in configuration.items():
            parent = anchor(stack, os.path.dirname(path), links)
            leaf = os.path.basename(path)
            value, original = read_file(parent, leaf, contract['DEP_SOURCE_LIMIT'])
            if not value[0]:
                raise ValueError("empty startup configuration input")
            configs[name] = (parent, leaf, value, original)
        manifest = {'schema': 1, 'app': app, 'commit': commit, 'tree': tree,
                    'profile': 'self-contained-net10-linux-x64', 'files': sorted(rows, key=lambda row: row['path']),
                    'configuration': {name: item[2][1] for name, item in configs.items()}}
        raw = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        digest = hashlib.sha256(raw).hexdigest()
        declaration = {'commit': commit, 'tree': tree, 'manifest_sha256': digest}
        files, directories, _, _ = contract['release_plan'](raw, app, declaration)
        runtime = contract['release_runtime'](app, files, observed)
        for role, root in roots.items():
            if inventory(root, contract) != inventories[role]:
                raise ValueError("publish tree changed before staging")
        check_links(links)
        # Everything above is read-only. An exclusive private output is retained
        # on failure for inspection; retries never adopt, delete or overwrite it.
        os.mkdir(output_leaf, 0o700, dir_fd=target_parent)
        target = os.open(output_leaf, READ | os.O_DIRECTORY, dir_fd=target_parent)
        stack.callback(os.close, target)
        target_base = base(os.fstat(target))
        for directory in sorted(directories, key=lambda name: (name.count('/'), name)):
            with parent_for(target, directory) as (parent, leaf):
                os.mkdir(leaf, 0o700, dir_fd=parent)
        for name, row in files.items():
            role, relative = name.split('/', 1)
            with parent_for(roots[role], relative) as (source_parent, source_leaf), parent_for(target, name) as (parent, leaf):
                fd = create_file(parent, leaf)
                try:
                    value, _ = read_file(source_parent, source_leaf, contract['REL_FILE_LIMIT'], writer=fd,
                                         expected=inventories[role][relative])
                    if value[:2] != (row['bytes'], row['sha256']):
                        raise ValueError("publish bytes changed before copy")
                    os.fchmod(fd, int(row['mode'], 8))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                copied, _ = read_file(parent, leaf, contract['REL_FILE_LIMIT'])
                if copied[:2] != (row['bytes'], row['sha256']):
                    raise ValueError("staged file readback mismatch")
        for role, root in roots.items():
            if inventory(root, contract) != inventories[role]:
                raise ValueError("publish tree changed during staging")
        for parent, leaf, expected, original in configs.values():
            current, _ = read_file(parent, leaf, contract['DEP_SOURCE_LIMIT'], expected=original)
            if current != expected:
                raise ValueError("configuration changed during staging")
        check_links(links)
        fd = create_file(target, 'release.json')
        try:
            write_all(fd, raw)
            os.fchmod(fd, 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)
        copied, _ = read_file(target, 'release.json', contract['REL_MANIFEST_LIMIT'], capture=True)
        if copied[2] != raw:
            raise ValueError("staged manifest readback mismatch")
        for directory in sorted(directories, key=lambda name: (name.count('/'), name), reverse=True):
            with parent_for(target, directory) as (parent, leaf):
                fd = os.open(leaf, READ | os.O_DIRECTORY, dir_fd=parent)
                try:
                    os.fchmod(fd, 0o755)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        if base(os.stat(output_leaf, dir_fd=target_parent, follow_symlinks=False)) != target_base:
            raise ValueError("staged directory identity changed")
        os.fchmod(target, 0o755)
        os.fsync(target)
        os.fsync(target_parent)
        inspect_release(target, app, declaration, contract)
        check_links(links)
    return {'scope': 'OFFLINE DEVELOPMENT RELEASE', 'application': app, 'output': output,
            'declaration': declaration, 'files': len(rows), 'payload_bytes': total, 'runtime': runtime,
            'configuration_copied': False, 'source_or_build_authenticated': False,
            'installed_ownership_admitted': False, 'application_executed': False, 'server_ready': False}


def bindings(values):
    result = {}
    for value in values:
        name, separator, path = value.partition('=')
        if not separator or not name or not path or name in result:
            raise ValueError("unique NAME=ABSOLUTE_PATH input required")
        result[name] = path
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'commit', 'tree'):
        parser.add_argument('--' + name, required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--output', help='new output below a private developer directory')
    operation.add_argument('--verify', help='existing release directory to inspect without writes')
    parser.add_argument('--manifest-sha256', help='required original manifest commitment for --verify')
    parser.add_argument('--role', action='append', default=[], metavar='ROLE=ABSOLUTE_PATH')
    parser.add_argument('--config', action='append', default=[], metavar='NAME=ABSOLUTE_PATH')
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if args.role or args.config:
                raise ValueError("verification takes a release and its pinned commitments only")
            result = verify(args.app, args.commit, args.tree, args.manifest_sha256, args.verify)
        else:
            if args.manifest_sha256 is not None:
                raise ValueError("staging computes its manifest commitment")
            result = stage(args.app, args.commit, args.tree, bindings(args.role), bindings(args.config), args.output)
    except (OSError, ValueError, TypeError, MemoryError, RecursionError, OverflowError):
        print('Development release staging refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

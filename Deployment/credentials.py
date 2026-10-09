"""Bind DNS nested inputs and produce an inactive owner-only preparation helper."""


DNS_CREDENTIAL_HELPER_PATH = '/usr/libexec/azurelinux3s4/dns-credentials.py'
DNS_CREDENTIAL_AUTHORITY = (
    'credential_intent_authenticated', 'key_material_authenticated', 'key_role_and_scope_validated',
    'database_connection_usable', 'complete_control_schema_validated', 'service_identity_provisioned',
    'systemd_credential_acl_validated', 'runtime_helper_installed', 'runtime_helper_executed',
    'application_credential_loading_proven', 'physical_durability_proven',
)


def dns_credential_observe(captured):
    plans = []
    for role, leaf in (('controller', 'control-plane.json'), ('authoritative-replica', 'authority.json')):
        runtime = '/run/mk8.dns/' + role + '/inputs/'
        value = release_json(captured[leaf])
        if value.get('KeyFile') != runtime + 'key.pem':
            raise ValueError('DNS role-owned key reference required')
        selected = {'control.json': ('/etc/mk8.dns/' + leaf, captured[leaf], 65536),
                    'key.pem': ('/etc/mk8.dns/' + role + '/key.pem', None, 4096)}
        if role == 'controller':
            if value.get('ConnectionStringFile') != runtime + 'database.txt':
                raise ValueError('DNS role-owned database reference required')
            selected['database.txt'] = ('/etc/mk8.dns/controller/database.txt', None, 4096)
        elif value.get('ConnectionStringFile') is not None:
            raise ValueError('replica cannot receive database credentials')
        zones = value.get('Zones')
        if type(zones) is not list or not 1 <= len(zones) <= 64:
            raise ValueError('DNS bounded zone references required')
        seen = set()
        for zone in zones:
            if (type(zone) is not dict or type(zone.get('ZoneId')) is not str
                    or not dep_re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', zone['ZoneId'])
                    or zone['ZoneId'] in seen):
                raise ValueError('DNS unique canonical zone identity required')
            seen.add(zone['ZoneId'])
            key = zone.get('SigningKeyFile')
            if key is None:
                continue
            name = 'zone-' + zone['ZoneId'] + '.pk8'
            if role != 'controller' or key != runtime + name:
                raise ValueError('DNS controller-owned signing key reference required')
            selected[name] = ('/etc/mk8.dns/controller/' + name, None, 4096)
        rows = []
        for name, (source, original, maximum) in sorted(selected.items()):
            data = deployment_read(source)
            if (not 0 < len(data) <= maximum or (original is not None and data != original)):
                raise ValueError('DNS credential size or original configuration correspondence')
            rows.append({'id': name, 'source': source, 'destination': runtime + name,
                         'bytes': len(data), 'sha256': dep_hash.sha256(data).hexdigest(),
                         'source_mode': '0600', 'destination_mode': '0400',
                         'checked_original_readback_and_close': True})
        plans.append({'role': role, 'unit': 'mk8-dns-' + role + '.service', 'inputs': rows,
                      'runtime_directory': runtime[:-1],
                      'authority': {name: False for name in DNS_CREDENTIAL_AUTHORITY}})
    return plans


def dns_credential_unit(plan):
    arguments = [plan['role']] + [row['id'] + ':' + str(row['bytes']) + ':' + row['sha256']
                                for row in plan['inputs']]
    return tuple('LoadCredential=' + row['id'] + ':' + row['source'] for row in plan['inputs']) + (
        'ExecStartPre=/usr/bin/python3 -I ' + DNS_CREDENTIAL_HELPER_PATH + ' ' + ' '.join(arguments),)


# This is a future ExecStartPre program, returned as inactive candidate bytes.
# It never runs in the candidate observer. It assumes an honest PID1 credential
# delivery and the already provisioned non-root service identity/runtime leaf.
DNS_CREDENTIAL_PROGRAM = r'''"""Copy checked per-unit DNS inputs into a fresh owner-only runtime leaf."""
import contextlib
import hashlib
import os
import re
import resource
import stat
import sys

ROOT_UID = 0
OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(info, owners):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022:
        raise ValueError('unprotected credential directory')


@contextlib.contextmanager
def held_directory(path, uid, runtime=False):
    with contextlib.ExitStack() as stack:
        root = os.open('/', OPEN | os.O_DIRECTORY)
        stack.callback(os.close, root)
        before_root = os.fstat(root)
        directory(before_root, (ROOT_UID,))
        held, links, parent = [(root, before_root)], [], root
        parts = path[1:].split('/')
        for index, name in enumerate(parts):
            owners = (uid,) if runtime and index == len(parts) - 1 else (ROOT_UID, uid) if index == len(parts) - 1 else (ROOT_UID,)
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            directory(before, owners)
            child = os.open(name, OPEN | os.O_DIRECTORY, dir_fd=parent)
            stack.callback(os.close, child)
            current = os.fstat(child)
            if identity(before) != identity(current):
                raise ValueError('credential directory changed on open')
            links.append((parent, name, child, owners))
            held.append((child, current))
            parent = child
        if runtime and stat.S_IMODE(os.fstat(parent).st_mode) != 0o700:
            raise ValueError('owner-only runtime directory required')
        yield parent
        # Our exclusive mkdir changes only the final runtime directory metadata.
        if runtime:
            current = os.fstat(parent)
            if identity(current)[:5] != identity(held[-1][1])[:5]:
                raise ValueError('runtime owner or identity changed')
            held[-1] = (parent, current)
        for fd, previous in held:
            if identity(os.fstat(fd)) != identity(previous):
                raise ValueError('held credential ancestry changed')
        for pfd, name, fd, owners in links:
            current = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            directory(current, owners)
            if identity(current) != identity(os.fstat(fd)):
                raise ValueError('credential ancestry path changed')
        fresh = os.open('/', OPEN | os.O_DIRECTORY)
        stack.callback(os.close, fresh)
        if identity(os.fstat(fresh)) != identity(before_root):
            raise ValueError('credential root changed')


def bytes_from(fd, maximum):
    result = bytearray()
    while True:
        data = os.read(fd, min(8192, maximum + 1 - len(result)))
        if not data:
            return bytes(result)
        result.extend(data)
        if len(result) > maximum:
            raise ValueError('credential EOF bound')


def checked_bytes(fd, expected):
    os.lseek(fd, 0, os.SEEK_SET)
    first = bytes_from(fd, expected[0])
    os.lseek(fd, 0, os.SEEK_SET)
    second = bytes_from(fd, expected[0])
    if first != second or len(first) != expected[0] or hashlib.sha256(first).hexdigest() != expected[1]:
        raise ValueError('credential original-byte commitment')
    return first


def source_bytes(parent, name, expected, uid, owned=False):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid not in ((uid,) if owned else (ROOT_UID, uid))
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in ((0o400,) if owned else (0o400, 0o440))
            or before.st_size != expected[0]):
        raise ValueError('bounded read-only PID1 credential required')
    fd = os.open(name, OPEN, dir_fd=parent)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('credential changed on open')
        data = checked_bytes(fd, expected)
        if (identity(os.fstat(fd)) != identity(before)
                or identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(before)):
            raise ValueError('credential source changed')
    finally:
        os.close(fd)
    return data


def output_bytes(parent, name, data, expected, uid):
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if not 0 < written <= len(view):
                raise ValueError('credential short write')
            view = view[written:]
        os.fchmod(fd, 0o400)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o400 or before.st_size != expected[0]):
            raise ValueError('owner-only credential output required')
        checked_bytes(fd, expected)
        if (identity(os.fstat(fd)) != identity(before)
                or identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(before)):
            raise ValueError('credential output changed')
    finally:
        os.close(fd)


def names(fd):
    result = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(result) == 67:
                raise ValueError('credential directory entry bound')
            result.add(entry.name)
    return result


def prepare(arguments):
    if not 3 <= len(arguments) <= 68 or arguments[0] not in ('controller', 'authoritative-replica'):
        raise ValueError('bounded DNS role and commitments required')
    role, rows = arguments[0], {}
    for text in arguments[1:]:
        match = re.fullmatch(r'(control\.json|key\.pem|database\.txt|zone-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.pk8):([1-9][0-9]{0,4}):([0-9a-f]{64})', text)
        if not match or match[1] in rows:
            raise ValueError('unique credential commitments required')
        name, size = match[1], int(match[2])
        if size > (65536 if name == 'control.json' else 4096):
            raise ValueError('credential byte bound')
        rows[name] = (size, match[3])
    if (list(rows) != sorted(rows) or not {'control.json', 'key.pem'} <= rows.keys()
            or (role == 'controller' and 'database.txt' not in rows)
            or (role == 'authoritative-replica' and set(rows) != {'control.json', 'key.pem'})):
        raise ValueError('complete role-specific credential set required')
    uid = os.geteuid()
    if uid == ROOT_UID:
        raise ValueError('provisioned non-root DNS identity required')
    source = '/run/credentials/mk8-dns-' + role + '.service'
    if os.environ.get('CREDENTIALS_DIRECTORY') != source:
        raise ValueError('exact per-unit PID1 credential directory required')
    with held_directory(source, uid) as source_fd, held_directory('/run/mk8.dns/' + role, uid, True) as runtime_fd:
        if names(source_fd) != rows.keys():
            raise ValueError('complete credential directory required')
        # All source files are admitted before any runtime write. Existing inputs
        # always refuse; never adopt, overwrite or remove peer/partial/foreign data.
        originals = {name: source_bytes(source_fd, name, expected, uid) for name, expected in rows.items()}
        os.mkdir('inputs', mode=0o700, dir_fd=runtime_fd)
        created = os.stat('inputs', dir_fd=runtime_fd, follow_symlinks=False)
        target_fd = os.open('inputs', OPEN | os.O_DIRECTORY, dir_fd=runtime_fd)
        try:
            start = os.fstat(target_fd)
            if (identity(created) != identity(start) or not stat.S_ISDIR(start.st_mode)
                    or start.st_uid != uid or stat.S_IMODE(start.st_mode) != 0o700):
                raise ValueError('exclusive owner-only input directory required')
            for name, expected in rows.items():
                output_bytes(target_fd, name, originals[name], expected, uid)
            if names(target_fd) != rows.keys() or names(source_fd) != rows.keys():
                raise ValueError('credential directory membership changed')
            for name, expected in rows.items():
                if source_bytes(source_fd, name, expected, uid) != originals[name]:
                    raise ValueError('credential source changed after copy')
                source_bytes(target_fd, name, expected, uid, True)
            current = os.fstat(target_fd)
            if (current.st_dev, current.st_ino, current.st_mode, current.st_uid) != (start.st_dev, start.st_ino, start.st_mode, start.st_uid):
                raise ValueError('input directory identity changed')
            if identity(os.stat('inputs', dir_fd=runtime_fd, follow_symlinks=False)) != identity(current):
                raise ValueError('input directory path changed')
        finally:
            os.close(target_fd)


def main():
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 35))
        resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        prepare(sys.argv[1:])
    except (OSError, ValueError, TypeError, MemoryError, OverflowError):
        print('DNS credential preparation refused', file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
'''

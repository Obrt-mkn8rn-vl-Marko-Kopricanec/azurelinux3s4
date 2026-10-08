"""Observe protected local admin records without NSS lookup or account changes."""

from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
import re
import resource
import stat
import sys


ADMIN = 'azurelinux3s4-admin'
HOME_PATH = '/home/' + ADMIN
SHELL_PATHS = ('/bin/bash', '/usr/bin/bash')
TRUSTED_UID = 0
SOURCE_LIMIT = 1024 * 1024
RECORD_LIMIT = 16384
NAME = re.compile(r'[a-z_][a-z0-9_.-]{0,31}\$?\Z', re.ASCII)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def trusted(value, kind):
    if value.st_uid != TRUSTED_UID or value.st_mode & 0o022 or not kind(value.st_mode):
        raise ValueError('local account source has unsupported type, ownership or permissions')


def root_open():
    return os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)


def read_file(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    pieces, size = [], 0
    while True:
        piece = os.read(descriptor, min(65536, SOURCE_LIMIT + 1 - size))
        if not piece: break
        pieces.append(piece); size += len(piece)
        if size > SOURCE_LIMIT: raise ValueError('local account source exceeds bound')
    return b''.join(pieces)


@contextmanager
def database_snapshot():
    # Literal paths anchored at held protected root/etc descriptors. No NSS or
    # shadow calls, ancestry aliases, source repair or pathname-based mutation.
    with ExitStack() as stack:
        root = root_open(); stack.callback(os.close, root)
        root_identity = identity(os.fstat(root)); trusted(os.fstat(root), stat.S_ISDIR)
        before = os.stat('etc', dir_fd=root, follow_symlinks=False); trusted(before, stat.S_ISDIR)
        directory = os.open('etc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root)
        stack.callback(os.close, directory)
        directory_identity = identity(os.fstat(directory))
        if directory_identity != identity(before): raise ValueError('account source ancestry changed')
        content, observed, descriptors = {}, {}, {}
        for name in ('passwd', 'group', 'shells'):
            before = os.stat(name, dir_fd=directory, follow_symlinks=False); trusted(before, stat.S_ISREG)
            if not 0 < before.st_size <= SOURCE_LIMIT: raise ValueError('empty or excessive local account source')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            stack.callback(os.close, fd)
            if identity(os.fstat(fd)) != identity(before): raise ValueError('local account leaf changed before read')
            data = read_file(fd)
            if len(data) != before.st_size or identity(os.fstat(fd)) != identity(before):
                raise ValueError('local account source changed during read')
            content[name], observed[name], descriptors[name] = data, identity(before), fd
        yield content
        # Require a second whole read of each held regular object and fresh
        # namespace/ancestry observations before releasing the observation.
        for name, fd in descriptors.items():
            if (read_file(fd) != content[name] or identity(os.fstat(fd)) != observed[name]
                    or identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != observed[name]):
                raise ValueError('local account snapshot or namespace changed')
        fresh_root = root_open(); stack.callback(os.close, fresh_root)
        if (identity(os.fstat(root)) != root_identity or identity(os.fstat(fresh_root)) != root_identity
                or identity(os.fstat(directory)) != directory_identity
                or identity(os.stat('etc', dir_fd=fresh_root, follow_symlinks=False)) != directory_identity):
            raise ValueError('local account ancestry changed during observation')
        # ExitStack checks ordinary descriptor closes before caller success.


def lines(data):
    if (not 0 < len(data) <= SOURCE_LIMIT or not data.endswith(b'\n')
            or any(value < 32 and value != 10 or value == 127 for value in data)):
        raise ValueError('unsupported local account source encoding or lines')
    # Local records end at byte LF; Unicode splitlines would invent entries.
    # Account for every raw record, including comments/empties, before decoding.
    raw = data[:-1].split(b'\n')
    if len(raw) > RECORD_LIMIT or any(len(value) > 4096 for value in raw):
        raise ValueError('local account record bounds exceeded')
    values = [value.decode('utf-8') for value in raw]
    if any('\x80' <= character <= '\x9f' or character in '\u2028\u2029'
           for value in values for character in value):
        raise ValueError('unsupported non-LF Unicode separator or control')
    return [value for value in values if value and not value.startswith('#')]


def number(value):
    if not re.fullmatch(r'0|[1-9][0-9]{0,9}', value, flags=re.ASCII) or int(value) > 4294967294:
        raise ValueError('unsupported local numeric identity')
    return int(value)


def records(data, kind):
    values = {}
    for line in lines(data):
        fields = line.split(':')
        if (len(fields) != (7 if kind == 'passwd' else 4) or not NAME.fullmatch(fields[0])
                or fields[0] in values or fields[1] not in ('x', '*', '!', '!!', '')):
            raise ValueError('unsupported, duplicate or credential-bearing local account record')
        if kind == 'passwd':
            values[fields[0]] = {'name': fields[0], 'uid': number(fields[2]), 'gid': number(fields[3]),
                                 'home': fields[5], 'shell': fields[6]}
        else:
            members = fields[3].split(',') if fields[3] else []
            if len(members) != len(set(members)) or any(not NAME.fullmatch(value) for value in members):
                raise ValueError('unsupported or repeated local group membership')
            values[fields[0]] = {'name': fields[0], 'gid': number(fields[2]), 'members': members}
    return values


def classify(content):
    users, groups = records(content['passwd'], 'passwd'), records(content['group'], 'group')
    if (users.get('root', {}).get('uid') != 0 or users['root']['gid'] != 0
            or groups.get('root', {}).get('gid') != 0):
        raise ValueError('local root baseline is missing or unsupported')
    shells = lines(content['shells'])
    if (not shells or len(shells) != len(set(shells)) or any(not value.startswith('/') or value == '/'
            or '//' in value or any(part in ('.', '..') for part in value.split('/'))
            or value.endswith('/') or any(character.isspace() for character in value) for value in shells)):
        raise ValueError('local shell registration is unsupported')
    user, group = users.get(ADMIN), groups.get(ADMIN)
    memberships = [entry['name'] for entry in groups.values() if ADMIN in entry['members']]
    if user is None:
        if group is not None or memberships: raise ValueError('administrator name has local group residue or collision')
        return {'local_status': 'absent', 'account': None, 'local_supplementary_groups': []}
    if (group is None or not 1000 <= user['uid'] <= 60000 or not 1000 <= user['gid'] <= 60000
            or user['gid'] != group['gid'] or user['home'] != HOME_PATH or user['shell'] not in SHELL_PATHS
            or user['shell'] not in shells):
        raise ValueError('existing administrator record does not match the prospective local profile')
    if (sum(entry['uid'] == user['uid'] for entry in users.values()) != 1
            or sum(entry['gid'] == user['gid'] for entry in groups.values()) != 1
            or any(entry['name'] != ADMIN and entry['gid'] == user['gid'] for entry in users.values())
            or set(group['members']) - {ADMIN} or set(memberships) - {ADMIN}):
        raise ValueError('administrator numeric identity or local groups are shared or privileged')
    return {'local_status': 'present', 'account': user, 'local_supplementary_groups': []}


def observe():
    with database_snapshot() as content:
        classification = classify(content)
        sources = {name: {'path': '/etc/' + name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                   for name, data in content.items()}
    return {
        'scope': 'PROTECTED LOCAL ADMINISTRATOR RECORD / GROUP / SHELL-REGISTRATION OBSERVATIONS ONLY',
        'administrator_name': ADMIN, **classification, 'sources': sources,
        'authority': {name: False for name in (
            'existing_identity_authorized', 'nss_resolution_proven', 'uid_gid_reserved', 'account_created',
            'account_adoption_authorized', 'shadow_password_or_expiry_state_admitted', 'pam_policy_admitted',
            'shell_executable_or_loadable_proven', 'home_directory_admitted', 'kernel_groups_admitted',
            'sudo_or_privilege_policy_satisfied', 'credentials_provisioned', 'local_origin_proven',
            'ssh_authentication_executed', 'installation_authorized', 'server_ready')},
        'limits': [
            'Local file records only, not NSS/directory-service existence or effective kernel memberships. '
            'Absence is not permission to allocate UID/GID or create an account; matching presence is not permission '
            'to reuse an identity. Source files are not authentication or owner intent.',
            'The prospective profile uses private same-name primary group, UID/GID1000..60000, fixed home and registered '
            'bash spelling without local supplementary memberships. This is repository policy, not vendor allocator '
            'configuration, shell binary/ACL/LSM/capability/noexec/loadability or home-filesystem admission.',
            'No shadow/gshadow, PAM, NSS, sudoers, credentials or interpreter execution. Password storage fields '
            'and GECOS are not emitted; inline credential-bearing/unsupported records defer. Missing/unsafe/malformed '
            'sources are not converted into absence or repaired.',
            'Held protected no-follow root/etc/regular snapshots, two reads and namespace/metadata observations are '
            'sequential, not atomic/ABA/concurrent-root, content authenticity or physical durability guarantees. '
            'Trusted root/kernel/base/Python/private ancestry and finite honest IO/scheduling remain assumptions. '
            'No account/installation/SSH/PAM/privilege/recovery/target-Azure/ARM/full-server enforcement follows.'
        ],
    }


def main():
    if len(sys.argv) != 1: return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = observe()
    except (OSError, ValueError):
        print('SSH local account observation refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': sys.exit(main())

"""Observe a fixed administrator home and named startup files; never apply it."""

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import resource
import stat
import sys


HOME_ADMIN = 'azurelinux3s4-admin'
HOME_FIXED_PATH = '/home/' + HOME_ADMIN
HOME_OWNER_UID = 0
HOME_OWNER_GID = 0
HOME_FILE_LIMIT = 512 * 1024
HOME_STARTUPS = ('.bash_profile', '.bash_login', '.profile', '.bashrc', '.bash_logout')


def home_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def home_root_open():
    return os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)


def home_trusted(value, kind, modes=None, root_group=False):
    if (not kind(value.st_mode) or value.st_uid != HOME_OWNER_UID or value.st_mode & 0o022
            or root_group and value.st_gid != HOME_OWNER_GID
            or modes is not None and stat.S_IMODE(value.st_mode) not in modes):
        raise ValueError('unsupported administrator home object')


def home_read(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    parts, size = [], 0
    while True:
        value = os.read(descriptor, min(65536, HOME_FILE_LIMIT + 1 - size))
        if not value: return b''.join(parts)
        parts.append(value); size += len(value)
        if size > HOME_FILE_LIMIT: raise ValueError('administrator startup source exceeds bound')


@contextmanager
def home_namespace(local_status):
    with ExitStack() as stack:
        root = home_root_open(); stack.callback(os.close, root)
        root_value = home_identity(os.fstat(root)); home_trusted(os.fstat(root), stat.S_ISDIR)
        directories, files, missing, observations = [], [], [], []

        def directory(parent, name, path, modes=None, root_group=False):
            try: before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                missing.append((parent, name)); observations.append({'path': path, 'kind': 'directory', 'status': 'absent'})
                return None
            home_trusted(before, stat.S_ISDIR, modes, root_group)
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, descriptor)
            if home_identity(os.fstat(descriptor)) != home_identity(before): raise ValueError('home directory changed before admission')
            directories.append((parent, name, descriptor, home_identity(before)))
            observations.append({'path': path, 'kind': 'directory', 'status': 'present',
                                 'uid': before.st_uid, 'gid': before.st_gid, 'mode': f'{stat.S_IMODE(before.st_mode):04o}'})
            return descriptor

        def leaf(parent, name, path):
            try: before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                missing.append((parent, name)); observations.append({'path': path, 'kind': 'startup', 'status': 'absent'})
                return
            home_trusted(before, stat.S_ISREG, (0o444, 0o644), True)
            if before.st_nlink != 1 or before.st_size > HOME_FILE_LIMIT:
                raise ValueError('unsupported linked or excessive startup source')
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, descriptor)
            if home_identity(os.fstat(descriptor)) != home_identity(before): raise ValueError('startup leaf changed before read')
            data = home_read(descriptor)
            if len(data) != before.st_size or home_identity(os.fstat(descriptor)) != home_identity(before):
                raise ValueError('startup source changed during read')
            files.append((parent, name, descriptor, home_identity(before), data))
            observations.append({'path': path, 'kind': 'startup', 'status': 'present', 'bytes': len(data),
                                 'sha256': hashlib.sha256(data).hexdigest(), 'uid': before.st_uid,
                                 'gid': before.st_gid, 'mode': f'{stat.S_IMODE(before.st_mode):04o}'})

        parent = directory(root, 'home', '/home')
        target = directory(parent, HOME_ADMIN, HOME_FIXED_PATH, (0o755,), True) if parent is not None else None
        if target is not None:
            if local_status != 'present': raise ValueError('home exists without matching local account record')
            for name in HOME_STARTUPS: leaf(target, name, HOME_FIXED_PATH + '/' + name)
            ssh = directory(target, '.ssh', HOME_FIXED_PATH + '/.ssh', (0o700, 0o755), True)
            if ssh is not None: leaf(ssh, 'rc', HOME_FIXED_PATH + '/.ssh/rc')
        yield {'home_status': 'present' if target is not None else 'absent', 'objects': observations}
        # Caller repeats account observations while all namespace descriptors
        # remain held. Recheck bytes, identities and absences before closure.
        for parent, name, descriptor, before, data in files:
            if (home_read(descriptor) != data or home_identity(os.fstat(descriptor)) != before
                    or home_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
                raise ValueError('startup snapshot or namespace changed')
        for parent, name, descriptor, before in directories:
            if (home_identity(os.fstat(descriptor)) != before
                    or home_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
                raise ValueError('home directory namespace changed')
        for parent, name in missing:
            try: os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError('absent home object appeared')
        fresh = home_root_open(); stack.callback(os.close, fresh)
        if home_identity(os.fstat(root)) != root_value or home_identity(os.fstat(fresh)) != root_value:
            raise ValueError('home root namespace changed')
        # Checked ExitStack closes precede caller success, including empty data.


def home_account_view(value):
    if (not isinstance(value, dict) or value.get('administrator_name') != HOME_ADMIN
            or value.get('local_status') not in ('absent', 'present')
            or not isinstance(value.get('authority'), dict) or len(value['authority']) != 16
            or any(flag is not False for flag in value['authority'].values())
            or value['local_status'] == 'absent' and value.get('account') is not None
            or value['local_status'] == 'present' and (not isinstance(value.get('account'), dict)
                or value['account'].get('name') != HOME_ADMIN or value['account'].get('home') != HOME_FIXED_PATH)):
        raise ValueError('unsupported local account observation')
    return value


def home_observe(account_observer):
    before = home_account_view(account_observer())
    with home_namespace(before['local_status']) as namespace:
        after = home_account_view(account_observer())
        if before != after: raise ValueError('local account view changed during home observation')
        result = {
            'scope': 'LOCAL HOME AND NAMED STARTUP FILE OBSERVATIONS ONLY', 'administrator_name': HOME_ADMIN,
            'home_path': HOME_FIXED_PATH, 'local_account': before, **namespace,
            'authority': {name: False for name in (
                'account_adoption_authorized', 'home_adoption_authorized', 'creation_or_repair_authorized',
                'startup_contents_authenticated', 'startup_scripts_safe', 'startup_selection_complete',
                'complete_home_inventory', 'user_access_or_acl_policy_proven', 'mount_or_lsm_policy_satisfied',
                'combined_snapshot_atomic', 'nss_or_pam_admitted', 'credential_authority_proven',
                'shell_execution_proven', 'ssh_authentication_executed', 'installation_authorized', 'server_ready')},
            'limits': [
                'Prospective repository profile: home root-owned/root-group0755; optional .ssh root-owned0700/0755; '
                'six named regular startup leaves root-owned/root-group0444/0644, single-linked and bounded. '
                'This is stricter repository policy, not a universal OpenSSH home rule or permission to adopt objects.',
                'Opaque startup bytes are hashed, never emitted, decoded, sourced or executed. No full home inventory, '
                'global shell files, environment/startup selection, ACL/LSM/capability/mount or user-access proof. '
                'A protected existing script is not authenticated or safe to execute.',
                'Two equal qualified local account views bracket held home observations; complete byte/metadata/path '
                'and absence rechecks plus checked closes precede output. Observations remain sequential, '
                'non-atomic/non-ABA/non-concurrent-root, not source authenticity or durability guarantees. '
                'Missing/unsafe/operator objects are neither followed, changed, created nor deleted.',
                'No account/NSS/PAM, credential, locality, privilege, SSH, installation, boot/repair, Azure/ARM or '
                'full-server authority. Trusted root/kernel/base/Python/procfs/private ancestry and finite honest '
                'IO/scheduling remain assumptions; a permitted shell can still execute its own programs.'
            ],
        }
    return result


def home_main(account_observer):
    if len(sys.argv) != 1: return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 35))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = home_observe(account_observer)
    except (OSError, ValueError):
        print('SSH administrator home observation refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True))
    return 0

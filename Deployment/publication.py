"""Publish exact inactive candidates; never install or activate their contents."""

import ctypes as pub_ctypes
import fcntl as pub_fcntl


PUB_STORE = '/var/lib/azurelinux3s4/candidates'
PUB_LOCK = b'azurelinux3s4-inactive-publication-lock-v1\n'
PUB_DIRECTORIES = ('deployment', 'network', 'postgresql', 'ssh')
PUB_FILES = ('ssh/sshd_config', 'network/host.nft', 'postgresql/listener.conf',
             'postgresql/pg_hba.conf', 'deployment/application-contract.json')
PUB_LIMIT = 1024 * 1024
PUB_AUTHORITY = ('manifest_authenticated', 'topology_assigned', 'original_client_admitted',
                 'release_authenticated', 'credentials_admitted', 'native_parsers_passed',
                 'target_runtime_admitted', 'host_configuration_installed', 'firewall_loaded',
                 'service_enabled', 'service_started', 'application_healthy',
                 'database_provisioned', 'tls_dns_mail_ready', 'backup_restore_proven',
                 'boot_update_rollback_proven', 'ssh_performance_measured',
                 'physical_power_loss_proven', 'concurrent_root_safety', 'server_ready')


def publication_encoded(value):
    return (dep_json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def publication_plan(data, ssh_producer):
    # Production has exactly one accepted, fixed producer; no supplied JSON is trusted.
    candidate = deployment_bundle(data, ssh_producer)
    if tuple(item['file'] for item in candidate['files']) != PUB_FILES:
        raise ValueError('complete fixed candidate file set required')
    contents = {'manifest.json': data, 'candidate.json': publication_encoded(candidate)}
    rows = []
    for entry in candidate['files']:
        raw = entry['content'].encode('ascii')
        if (entry['mode'] not in ('0600', '0644') or not raw.endswith(b'\n')
                or entry['bytes'] != len(raw) or entry['sha256'] != dep_hash.sha256(raw).hexdigest()):
            raise ValueError('candidate byte/mode commitment mismatch')
        contents[entry['file']] = raw
        rows.append({key: entry[key] for key in ('file', 'mode', 'bytes', 'sha256')})
    if sum(map(len, contents.values())) > PUB_LIMIT:
        raise ValueError('complete publication bound')
    intent = publication_encoded({'format': 'azurelinux3s4-inactive-candidate-v1',
                                  'source': candidate['source'], 'candidate': {'bytes': len(contents['candidate.json']),
                                  'sha256': dep_hash.sha256(contents['candidate.json']).hexdigest()},
                                  'files': rows, 'stored_leaf_mode': '0400', 'directory_mode': '0700',
                                  'activation_authorized': False})
    contents['publication.json'] = intent
    return dep_hash.sha256(intent).hexdigest(), contents


def publication_base(info):
    # These fields stay fixed during this publisher's intentional directory changes.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def publication_private(info, device):
    if (not dep_stat.S_ISDIR(info.st_mode) or info.st_uid != DEP_TRUSTED_UID
            or info.st_gid != DEP_TRUSTED_UID or dep_stat.S_IMODE(info.st_mode) != 0o700
            or info.st_dev != device):
        raise ValueError('private same-device publication directory required')


def publication_open_directory(stack, parent, name, device):
    before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
    publication_private(before, device)
    fd = dep_os.open(name, DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=parent)
    stack.callback(dep_os.close, fd)
    if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
        raise ValueError('publication directory changed on open')
    return fd, before


def publication_file(parent, name, expected, partial=False):
    before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not dep_stat.S_ISREG(before.st_mode) or before.st_uid != DEP_TRUSTED_UID
            or before.st_gid != DEP_TRUSTED_UID or before.st_nlink != 1
            or before.st_dev != dep_os.fstat(parent).st_dev
            or dep_stat.S_IMODE(before.st_mode) not in ((0o400, 0o600) if partial else (0o400,))
            or not 0 <= before.st_size <= len(expected)):
        raise ValueError('unqualified publication leaf')
    with dep_context.ExitStack() as stack:
        fd = dep_os.open(name, DEP_OPEN, dir_fd=parent)
        stack.callback(dep_os.close, fd)
        if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
            raise ValueError('publication leaf changed on open')
        reads = []
        for _ in range(2):
            dep_os.lseek(fd, 0, dep_os.SEEK_SET)
            raw = bytearray()
            while True:
                chunk = dep_os.read(fd, min(8192, len(expected) + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > len(expected):
                    raise ValueError('publication EOF bound')
            reads.append(bytes(raw))
        if (reads[0] != reads[1] or len(reads[0]) != before.st_size
                or (not expected.startswith(reads[0]) if partial else reads[0] != expected)):
            raise ValueError('publication bytes mismatch')
        for current in (dep_os.fstat(fd), dep_os.stat(name, dir_fd=parent, follow_symlinks=False)):
            if deployment_identity(current) != deployment_identity(before):
                raise ValueError('publication leaf changed')
    return before, reads[0]


def publication_write(parent, name, raw):
    # O_EXCL is independent of prior inspection. Never truncate an existing object.
    with dep_context.ExitStack() as stack:
        fd = dep_os.open(name, dep_os.O_RDWR | dep_os.O_CREAT | dep_os.O_EXCL
                         | dep_os.O_NOFOLLOW | dep_os.O_NONBLOCK | dep_os.O_CLOEXEC, 0o600, dir_fd=parent)
        stack.callback(dep_os.close, fd)
        initial = dep_os.fstat(fd)
        if (not dep_stat.S_ISREG(initial.st_mode) or initial.st_uid != DEP_TRUSTED_UID
                or initial.st_gid != DEP_TRUSTED_UID or initial.st_nlink != 1
                or dep_stat.S_IMODE(initial.st_mode) != 0o600 or initial.st_size != 0):
            raise ValueError('new publication leaf admission')
        offset = 0
        while offset < len(raw):
            count = dep_os.write(fd, raw[offset:])
            if type(count) is not int or not 0 < count <= len(raw) - offset:
                raise ValueError('incomplete publication write')
            offset += count
        dep_os.fchmod(fd, 0o400)
        dep_os.fsync(fd)
        if publication_base(dep_os.fstat(fd)) != (initial.st_dev, initial.st_ino,
                                                   dep_stat.S_IFREG | 0o400, initial.st_uid, initial.st_gid):
            raise ValueError('new publication identity changed')
    publication_file(parent, name, raw)
    dep_os.fsync(parent)


def publication_entries(fd):
    result = set()
    with dep_os.scandir(fd) as entries:
        for entry in entries:
            if len(result) == 12 or len(entry.name) > 64:
                raise ValueError('publication directory entry bound')
            result.add(entry.name)
    return result


def publication_tree(parent, name, contents, partial=False, directories_profile=PUB_DIRECTORIES):
    device = dep_os.fstat(parent).st_dev
    with dep_context.ExitStack() as stack:
        fd, initial = publication_open_directory(stack, parent, name, device)
        directories = {'': fd}
        observed = [(parent, name, fd, initial)]
        entries = publication_entries(fd)
        allowed = {'manifest.json', 'candidate.json', 'publication.json', *directories_profile}
        if not entries <= allowed or (not partial and entries != allowed):
            raise ValueError('unexpected publication root entries')
        # This complete exact marker is required before any partial-file recovery.
        publication_file(fd, 'publication.json', contents['publication.json'])
        for directory in directories_profile:
            if directory in entries:
                child, info = publication_open_directory(stack, fd, directory, device)
                directories[directory] = child
                observed.append((fd, directory, child, info))
        leaves = {}
        for directory, folder in directories.items():
            actual = publication_entries(folder)
            expected = {path.rsplit('/', 1)[-1] for path in contents if path.rpartition('/')[0] == directory}
            if directory == '':
                actual -= set(directories_profile)
            if not actual <= expected or (not partial and actual != expected):
                raise ValueError('unexpected publication directory entries')
            for leaf in sorted(actual):
                path = directory + '/' + leaf if directory else leaf
                leaves[path] = publication_file(folder, leaf, contents[path], partial and path != 'publication.json')
        # Directory metadata and complete second entry sets follow every leaf read/close.
        for directory, folder in directories.items():
            expected_entries = entries if directory == '' else {path.rsplit('/', 1)[-1] for path in leaves if path.rpartition('/')[0] == directory}
            if publication_entries(folder) != expected_entries:
                raise ValueError('publication entries changed')
        for directory, entry, held, before in observed:
            if (deployment_identity(dep_os.fstat(held)) != deployment_identity(before)
                    or deployment_identity(dep_os.stat(entry, dir_fd=directory, follow_symlinks=False)) != deployment_identity(before)):
                raise ValueError('publication directory changed')
    return leaves


def publication_rename(parent, source, target):
    # Linux/glibc contract, trusted base library; no overwrite fallback is provided.
    library = pub_ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, 'renameat2', None)
    if rename is None:
        raise ValueError('no-replace publication API unavailable')
    rename.argtypes = (pub_ctypes.c_int, pub_ctypes.c_char_p, pub_ctypes.c_int,
                       pub_ctypes.c_char_p, pub_ctypes.c_uint)
    rename.restype = pub_ctypes.c_int
    pub_ctypes.set_errno(0)
    result = rename(parent, source.encode('ascii'), parent, target.encode('ascii'), 1)
    if type(result) is not int or result != 0:
        raise OSError(pub_ctypes.get_errno(), 'no-replace publication refused')


def publication_sync_tree(parent, name, directories_profile=PUB_DIRECTORIES):
    with dep_context.ExitStack() as stack:
        fd, _ = publication_open_directory(stack, parent, name, dep_os.fstat(parent).st_dev)
        for directory in directories_profile:
            child, _ = publication_open_directory(stack, fd, directory, dep_os.fstat(parent).st_dev)
            for leaf in publication_entries(child):
                item = dep_os.open(leaf, DEP_OPEN, dir_fd=child)
                try:
                    dep_os.fsync(item)
                finally:
                    dep_os.close(item)
            dep_os.fsync(child)
        for leaf in ('manifest.json', 'candidate.json', 'publication.json'):
            item = dep_os.open(leaf, DEP_OPEN, dir_fd=fd)
            try:
                dep_os.fsync(item)
            finally:
                dep_os.close(item)
        dep_os.fsync(fd)
    dep_os.fsync(parent)


def publication_store(stack, store_path=PUB_STORE):
    parent = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
    stack.callback(dep_os.close, parent)
    initial_root = dep_os.fstat(parent)
    deployment_directory(initial_root)
    ancestors, links = [(parent, initial_root)], []
    parts = deployment_path(store_path)
    for index, name in enumerate(parts):
        before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
        deployment_directory(before)
        child = dep_os.open(name, DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=parent)
        stack.callback(dep_os.close, child)
        current = dep_os.fstat(child)
        if deployment_identity(current) != deployment_identity(before):
            raise ValueError('publication ancestry changed on open')
        links.append((parent, name, child, current))
        if index != len(parts) - 1:
            ancestors.append((child, current))
        parent = child
    publication_private(dep_os.fstat(parent), dep_os.fstat(parent).st_dev)
    return parent, ancestors, links


def publication_publish(data, ssh_producer, *, planner=None, store_path=PUB_STORE,
                        directories_profile=PUB_DIRECTORIES, lock_bytes=PUB_LOCK):
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('inactive publication requires root')
    digest, contents = (publication_plan if planner is None else planner)(data, ssh_producer)
    pending = '.pending-' + digest
    disposition = 'published'
    with dep_context.ExitStack() as stack:
        store, ancestors, links = publication_store(stack, store_path)
        try:
            dep_os.stat('.publisher.lock', dir_fd=store, follow_symlinks=False)
        except FileNotFoundError:
            publication_write(store, '.publisher.lock', lock_bytes)
        publication_file(store, '.publisher.lock', lock_bytes)
        lock = dep_os.open('.publisher.lock', DEP_OPEN, dir_fd=store)
        stack.callback(dep_os.close, lock)
        if deployment_identity(dep_os.fstat(lock)) != deployment_identity(dep_os.stat('.publisher.lock', dir_fd=store, follow_symlinks=False)):
            raise ValueError('publisher lock changed')
        pub_fcntl.flock(lock, pub_fcntl.LOCK_EX | pub_fcntl.LOCK_NB)
        publication_file(store, '.publisher.lock', lock_bytes)
        initial_lock = dep_os.fstat(lock)
        try:
            dep_os.stat(digest, dir_fd=store, follow_symlinks=False)
        except FileNotFoundError:
            try:
                dep_os.stat(pending, dir_fd=store, follow_symlinks=False)
            except FileNotFoundError:
                dep_os.mkdir(pending, 0o700, dir_fd=store)
                dep_os.fsync(store)
                with dep_context.ExitStack() as owner:
                    stage, _ = publication_open_directory(owner, store, pending, dep_os.fstat(store).st_dev)
                    publication_write(stage, 'publication.json', contents['publication.json'])
            else:
                disposition = 'recovered'
            previous = publication_tree(store, pending, contents, partial=True, directories_profile=directories_profile)
            with dep_context.ExitStack() as writing:
                stage, _ = publication_open_directory(writing, store, pending, dep_os.fstat(store).st_dev)
                directories = {'': stage}
                for name in directories_profile:
                    if name not in publication_entries(stage):
                        dep_os.mkdir(name, 0o700, dir_fd=stage)
                        dep_os.fsync(stage)
                    directories[name] = publication_open_directory(writing, stage, name, dep_os.fstat(store).st_dev)[0]
                for path, raw in contents.items():
                    parent_name, _, leaf = path.rpartition('/')
                    folder = directories[parent_name]
                    if path in previous:
                        before, captured = previous[path]
                        if deployment_identity(dep_os.stat(leaf, dir_fd=folder, follow_symlinks=False)) != deployment_identity(before):
                            raise ValueError('recovery leaf changed')
                        if captured == raw and dep_stat.S_IMODE(before.st_mode) == 0o400:
                            continue
                        dep_os.unlink(leaf, dir_fd=folder)
                        dep_os.fsync(folder)
                    publication_write(folder, leaf, raw)
            publication_tree(store, pending, contents, directories_profile=directories_profile)
            publication_sync_tree(store, pending, directories_profile)
            publication_tree(store, pending, contents, directories_profile=directories_profile)
            publication_rename(store, pending, digest)
            dep_os.fsync(store)
        else:
            disposition = 'already-present'
            # An extra pending tree is never adopted or silently deleted.
            try:
                dep_os.stat(pending, dir_fd=store, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('final and pending publication conflict')
        publication_tree(store, digest, contents, directories_profile=directories_profile)
        for current in (dep_os.fstat(lock), dep_os.stat('.publisher.lock', dir_fd=store, follow_symlinks=False)):
            if deployment_identity(current) != deployment_identity(initial_lock):
                raise ValueError('publisher lock identity changed')
        publication_sync_tree(store, digest, directories_profile)
        publication_tree(store, digest, contents, directories_profile=directories_profile)
        for fd, before in ancestors:
            deployment_directory(dep_os.fstat(fd))
            if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
                raise ValueError('publication ancestor changed')
        for parent, name, held, before in links:
            if (publication_base(dep_os.fstat(held)) != publication_base(before)
                    or publication_base(dep_os.stat(name, dir_fd=parent, follow_symlinks=False)) != publication_base(before)):
                raise ValueError('publication ancestry path changed')
        fresh = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
        stack.callback(dep_os.close, fresh)
        if deployment_identity(dep_os.fstat(fresh)) != deployment_identity(ancestors[0][1]):
            raise ValueError('publication root changed')
    return {'scope': 'INACTIVE EXACT CANDIDATE STORAGE ONLY', 'bundle': store_path + '/' + digest,
            'publication_sha256': digest, 'disposition': disposition,
            'source': {'bytes': len(data), 'sha256': dep_hash.sha256(data).hexdigest()},
            'stored_files': len(contents), 'stored_bytes': sum(map(len, contents.values())),
            'file_and_directory_fsync_returned': True, 'checked_closes_completed': True,
            'authority': {key: False for key in PUB_AUTHORITY},
            'limits': ['An existing protected 0700 root store is required; this command never creates host ancestry or activates files.',
                       'A valid exact ownership record permits recovery of exact prefixes only. Missing/partial/foreign records refuse without cleanup. Root ownership is not intent authentication.',
                       'Rename no-replace and flock apply to ordinary participants under trusted Linux/glibc/filesystem semantics, not concurrent-root/ABA/hostile-native containment.',
                       'After a write/close/fsync refusal, pending or even complete renamed bytes may remain. Retry freshly verifies and synchronizes; no failed invocation is success.',
                       'Observed fsync completion is not installed-disk/controller/power-loss proof. All original candidate/server/native/enforcement/application gates remain open.']}


def publication_main(ssh_producer):
    if len(dep_sys.argv) != 2:
        return 64
    try:
        dep_resource.setrlimit(dep_resource.RLIMIT_CPU, (30, 35))
        dep_resource.setrlimit(dep_resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        dep_resource.setrlimit(dep_resource.RLIMIT_CORE, (0, 0))
        path = dep_sys.argv[1]
        deployment_path(path)
        if path == PUB_STORE or path.startswith(PUB_STORE + '/'):
            raise ValueError('manifest must be outside publication storage')
        output = publication_encoded(publication_publish(deployment_read(path), ssh_producer))
    except (OSError, ValueError, TypeError, AttributeError, MemoryError, RecursionError, OverflowError):
        print('Inactive candidate publication refused', file=dep_sys.stderr)
        return 75
    print(output.decode('ascii'), end='')
    return 0

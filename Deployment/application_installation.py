"""Fixed application-file installer library; no CLI/default invokes this engine.

Future operational authorization, accounts, native parsing and lifecycle admission
are separate prerequisites. Development callers use explicitly private root IO.
"""


APP_INSTALL_STATE = '/var/lib/azurelinux3s4/application-installation'
APP_INSTALL_UNITS = '/etc/systemd/system'
APP_INSTALL_HELPERS = '/usr/libexec/azurelinux3s4'
APP_INSTALL_SYSUSERS = '/usr/lib/sysusers.d'
APP_INSTALL_LOCK = b'azurelinux3s4-application-file-installation-lock-v1\n'
APP_INSTALL_AUTHORITY = ('operationally_authorized', 'release_authenticated',
                        'configuration_authenticated', 'accounts_provisioned',
                        'native_unit_parser_passed', 'systemd_reloaded',
                        'service_enabled', 'service_started', 'application_healthy',
                        'database_provisioned', 'network_enforced', 'rollback_proven',
                        'boot_lifecycle_proven', 'physical_power_loss_proven',
                        'concurrent_root_safety', 'server_ready')


def application_installation_plan(data, ssh_producer):
    # No retained candidate, supplied planner, target path or receipt is accepted.
    digest, contents = application_publication_plan(data, ssh_producer)
    intent, _ = deployment_decode(contents['publication.json'])
    rows = intent['files']
    if (intent['format'] != 'azurelinux3s4-inactive-application-candidate-v1'
            or intent['activation_authorized'] is not False
            or type(rows) is not list or len(rows) not in (11, 12)):
        raise ValueError('complete fixed installation source required')
    payloads = []
    for row in rows:
        stored, mode = row['stored'], row['mode']
        if stored.startswith('systemd/'):
            leaf = stored[len('systemd/'):]
            if (not dep_re.fullmatch(r'mk8-(?:sava|drava|dns|email)-[a-z0-9-]+\.service', leaf)
                    or row['file'] != stored or mode != '0644'):
                raise ValueError('fixed systemd installation identity required')
            parent = APP_INSTALL_UNITS
        elif stored == 'sysusers/azurelinux3s4-applications.conf':
            leaf, parent = 'azurelinux3s4-applications.conf', APP_INSTALL_SYSUSERS
            if row['file'] != APP_ACCOUNT_FILE or mode != '0644':
                raise ValueError('fixed sysusers installation identity required')
        elif stored == 'helpers/dns-credentials.py':
            leaf, parent = 'dns-credentials.py', APP_INSTALL_HELPERS
            if row['file'] != 'usr/libexec/azurelinux3s4/' + leaf or mode != '0755':
                raise ValueError('fixed helper installation identity required')
        else:
            raise ValueError('unsupported application installation payload')
        raw = contents[stored]
        if (type(raw) is not bytes or not 0 < len(raw) <= APP_PUB_FILE_LIMIT
                or row['bytes'] != len(raw) or row['sha256'] != dep_hash.sha256(raw).hexdigest()):
            raise ValueError('installation payload commitment mismatch')
        payloads.append({'parent': parent, 'leaf': leaf, 'mode': int(mode, 8), 'raw': raw})
    paths = [row['parent'] + '/' + row['leaf'] for row in payloads]
    if len(set(paths)) != len(paths) or payloads[-1]['parent'] != APP_INSTALL_HELPERS:
        raise ValueError('complete unique ordered installation destinations required')
    record = publication_encoded({'format': 'azurelinux3s4-application-file-installation-v1',
                                  'publication_sha256': digest, 'source': intent['source'],
                                  'candidate': intent['candidate'],
                                  'files': [{'file': path, 'mode': format(row['mode'], '04o'),
                                             'bytes': len(row['raw']),
                                             'sha256': dep_hash.sha256(row['raw']).hexdigest()}
                                            for path, row in zip(paths, payloads)],
                                  'activation_authorized': False})
    if len(record) > DEP_SOURCE_LIMIT:
        raise ValueError('installation ownership record bound')
    return digest, record, payloads


def installation_directories(stack):
    root = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
    stack.callback(dep_os.close, root)
    deployment_directory(dep_os.fstat(root))
    held = {'/': (root, dep_os.fstat(root))}
    links = []
    for path in (APP_INSTALL_STATE, APP_INSTALL_UNITS, APP_INSTALL_HELPERS, APP_INSTALL_SYSUSERS):
        parent, prefix = root, ''
        for leaf in deployment_path(path):
            prefix += '/' + leaf
            if prefix in held:
                parent = held[prefix][0]
                continue
            before = dep_os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            deployment_directory(before)
            child = dep_os.open(leaf, DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=parent)
            stack.callback(dep_os.close, child)
            if deployment_identity(dep_os.fstat(child)) != deployment_identity(before):
                raise ValueError('installation directory changed on open')
            held[prefix] = (child, before)
            links.append((parent, leaf, child, before))
            parent = child
        if dep_os.fstat(parent).st_gid != DEP_TRUSTED_UID:
            raise ValueError('root-group installation destination required')
    state = held[APP_INSTALL_STATE][0]
    publication_private(dep_os.fstat(state), dep_os.fstat(state).st_dev)
    return held, links


def installation_context(held, links):
    mutable = (APP_INSTALL_STATE, APP_INSTALL_UNITS, APP_INSTALL_HELPERS, APP_INSTALL_SYSUSERS)
    for path, (fd, before) in held.items():
        current = dep_os.fstat(fd)
        deployment_directory(current)
        compare = publication_base if path in mutable else deployment_identity
        if compare(current) != compare(before):
            raise ValueError('installation held ancestry changed')
    for parent, leaf, fd, before in links:
        if (publication_base(dep_os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                != publication_base(before) or publication_base(dep_os.fstat(fd)) != publication_base(before)):
            raise ValueError('installation directory path changed')
    fresh = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
    try:
        if deployment_identity(dep_os.fstat(fresh)) != deployment_identity(held['/'][1]):
            raise ValueError('installation root changed')
    finally:
        dep_os.close(fresh)


def installation_leaf(parent, row, owned):
    try:
        before = dep_os.stat(row['leaf'], dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not owned:
        raise ValueError('existing destination lacks exact installation ownership')
    mode = dep_stat.S_IMODE(before.st_mode)
    if (not dep_stat.S_ISREG(before.st_mode) or before.st_uid != DEP_TRUSTED_UID
            or before.st_gid != DEP_TRUSTED_UID or before.st_nlink != 1
            or before.st_dev != dep_os.fstat(parent).st_dev
            or mode not in (0o600, row['mode']) or not 0 <= before.st_size <= len(row['raw'])):
        raise ValueError('unqualified owned installation leaf')
    fd = dep_os.open(row['leaf'], DEP_OPEN, dir_fd=parent)
    try:
        if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
            raise ValueError('installation leaf changed on open')
        reads = []
        for _ in range(2):
            dep_os.lseek(fd, 0, dep_os.SEEK_SET)
            raw = bytearray()
            while True:
                chunk = dep_os.read(fd, min(8192, len(row['raw']) + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > len(row['raw']):
                    raise ValueError('installation leaf EOF bound')
            reads.append(bytes(raw))
        if (reads[0] != reads[1] or len(reads[0]) != before.st_size
                or not row['raw'].startswith(reads[0])
                or (mode == row['mode'] and reads[0] != row['raw'])):
            raise ValueError('owned installation prefix/content mismatch')
        for current in (dep_os.fstat(fd), dep_os.stat(row['leaf'], dir_fd=parent, follow_symlinks=False)):
            if deployment_identity(current) != deployment_identity(before):
                raise ValueError('installation leaf changed on readback')
    finally:
        dep_os.close(fd)
    return before, reads[0]


def installation_write(parent, row, previous):
    if previous is not None and previous[1] == row['raw'] and dep_stat.S_IMODE(previous[0].st_mode) == row['mode']:
        return False
    flags = dep_os.O_RDWR | dep_os.O_NOFOLLOW | dep_os.O_NONBLOCK | dep_os.O_CLOEXEC
    if previous is None:
        flags |= dep_os.O_CREAT | dep_os.O_EXCL
    else:
        if deployment_identity(dep_os.stat(row['leaf'], dir_fd=parent, follow_symlinks=False)) != deployment_identity(previous[0]):
            raise ValueError('owned installation leaf changed before append')
    fd = dep_os.open(row['leaf'], flags, 0o600, dir_fd=parent)
    try:
        initial = dep_os.fstat(fd)
        offset = 0 if previous is None else len(previous[1])
        if (not dep_stat.S_ISREG(initial.st_mode) or initial.st_uid != DEP_TRUSTED_UID
                or initial.st_gid != DEP_TRUSTED_UID or initial.st_nlink != 1
                or dep_stat.S_IMODE(initial.st_mode) != 0o600 or initial.st_size != offset
                or initial.st_dev != dep_os.fstat(parent).st_dev
                or (previous is not None and deployment_identity(initial) != deployment_identity(previous[0]))):
            raise ValueError('exclusive/owned installation write admission')
        dep_os.lseek(fd, offset, dep_os.SEEK_SET)
        while offset < len(row['raw']):
            count = dep_os.write(fd, row['raw'][offset:])
            if type(count) is not int or not 0 < count <= len(row['raw']) - offset:
                raise ValueError('incomplete installation write')
            offset += count
        dep_os.fchmod(fd, row['mode'])
        dep_os.fsync(fd)
        if (publication_base(dep_os.fstat(fd)) != (initial.st_dev, initial.st_ino,
                dep_stat.S_IFREG | row['mode'], initial.st_uid, initial.st_gid)
                or dep_os.fstat(fd).st_nlink != 1):
            raise ValueError('installation write identity changed')
    finally:
        dep_os.close(fd)
    installation_leaf(parent, row, True)
    dep_os.fsync(parent)
    return True


def application_installation(data, ssh_producer):
    # Library only: no normal/default/CLI path calls this write-capable function.
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('application-file installation requires root')
    digest, record, rows = application_installation_plan(data, ssh_producer)
    changed = 0
    with dep_context.ExitStack() as stack:
        held, links = installation_directories(stack)
        state = held[APP_INSTALL_STATE][0]
        if not publication_entries(state) <= {'.installer.lock', 'installation.json'}:
            raise ValueError('foreign installation-state entries')
        try:
            dep_os.stat('installation.json', dir_fd=state, follow_symlinks=False)
        except FileNotFoundError:
            owned = False
        else:
            publication_file(state, 'installation.json', record)
            owned = True
        # Admit ALL fixed destinations before even creating the cooperative lock.
        for row in rows:
            installation_leaf(held[row['parent']][0], row, owned)
        installation_context(held, links)
        try:
            dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)
        except FileNotFoundError:
            publication_write(state, '.installer.lock', APP_INSTALL_LOCK)
        publication_file(state, '.installer.lock', APP_INSTALL_LOCK)
        lock = dep_os.open('.installer.lock', DEP_OPEN, dir_fd=state)
        stack.callback(dep_os.close, lock)
        initial_lock = dep_os.fstat(lock)
        if deployment_identity(initial_lock) != deployment_identity(dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)):
            raise ValueError('installer lock changed')
        pub_fcntl.flock(lock, pub_fcntl.LOCK_EX | pub_fcntl.LOCK_NB)
        publication_file(state, '.installer.lock', APP_INSTALL_LOCK)
        # Re-admit complete state and every leaf under the ordinary participant lock.
        if not publication_entries(state) <= {'.installer.lock', 'installation.json'}:
            raise ValueError('installation-state entries changed')
        if owned:
            publication_file(state, 'installation.json', record)
        else:
            try:
                dep_os.stat('installation.json', dir_fd=state, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('installation ownership appeared before lock')
        previous = [installation_leaf(held[row['parent']][0], row, owned) for row in rows]
        installation_context(held, links)
        if not owned:
            publication_write(state, 'installation.json', record)
        for row, old in zip(rows, previous):
            installation_context(held, links)
            changed += installation_write(held[row['parent']][0], row, old)
        for row in rows:
            parent = held[row['parent']][0]
            before, raw = installation_leaf(parent, row, True)
            if raw != row['raw'] or dep_stat.S_IMODE(before.st_mode) != row['mode']:
                raise ValueError('incomplete final installation set')
            fd = dep_os.open(row['leaf'], DEP_OPEN, dir_fd=parent)
            try:
                if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
                    raise ValueError('installation synchronization identity changed')
                dep_os.fsync(fd)
            finally:
                dep_os.close(fd)
            dep_os.fsync(parent)
        publication_file(state, 'installation.json', record)
        dep_os.fsync(state)
        for current in (dep_os.fstat(lock), dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)):
            if deployment_identity(current) != deployment_identity(initial_lock):
                raise ValueError('installer lock identity changed')
        installation_context(held, links)
    return {'scope': 'FIXED APPLICATION FILES ONLY; NO ACTIVATION',
            'publication_sha256': digest, 'installation_record_sha256': dep_hash.sha256(record).hexdigest(),
            'files': len(rows), 'changed_files': changed, 'checked_closes_completed': True,
            'file_and_directory_fsync_returned': True,
            'authority': {name: False for name in APP_INSTALL_AUTHORITY},
            'limits': ['Library is disconnected from CLI/defaults; operational authorization and target/native/lifecycle admission remain required.',
                       'All destination ancestry must already exist and be protected. Accounts, configuration, schema, systemd reload/enable/start and rollback are not supplied.',
                       'Exact ownership permits completion of known 0600 prefixes only; foreign, partial ownership records or changed plans refuse without deletion/overwrite.',
                       'Writes are sequential across files/directories, not pair/set atomic. Failures may leave files without success; no physical power-loss or concurrent-root/ABA guarantee.']}

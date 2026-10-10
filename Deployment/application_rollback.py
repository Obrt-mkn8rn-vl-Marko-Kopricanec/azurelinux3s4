"""Roll back owned first-installation files to absence; no CLI invokes this library.

No service/process/configuration/database rollback is supplied. Future operational
use requires separate authority and a checked stopped-manager/application context.
"""


APP_ROLLBACK_AUTHORITY = ('operationally_authorized', 'release_authenticated',
                         'configuration_authenticated', 'service_stopped',
                         'manager_state_admitted', 'processes_retired',
                         'configuration_rolled_back', 'database_rolled_back',
                         'application_healthy', 'boot_lifecycle_proven',
                         'physical_power_loss_proven', 'concurrent_root_safety',
                         'server_ready')


def application_rollback_plan(data, ssh_producer):
    digest, owner, rows = application_installation_plan(data, ssh_producer)
    marker = publication_encoded({'format': 'azurelinux3s4-application-file-rollback-v1',
                                  'publication_sha256': digest,
                                  'installation_record': {'bytes': len(owner),
                                                          'sha256': dep_hash.sha256(owner).hexdigest()},
                                  'files': len(rows), 'restored_destination_state': 'absent',
                                  'activation_authorized': False})
    return digest, owner, rows, marker


def rollback_absent(parent, leaf):
    try:
        dep_os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError('rollback destination unexpectedly present')


def rollback_admission(state, held, owner, rows, marker):
    entries = publication_entries(state)
    if not entries <= {'.installer.lock', 'installation.json', 'rollback.json'}:
        raise ValueError('foreign rollback-state entries')
    publication_file(state, '.installer.lock', APP_INSTALL_LOCK)
    recorded = 'rollback.json' in entries
    if recorded:
        publication_file(state, 'rollback.json', marker)
    owned = 'installation.json' in entries
    if owned:
        publication_file(state, 'installation.json', owner)
    elif not recorded:
        raise ValueError('exact installation or completed rollback ownership required')
    previous = []
    for row in rows:
        if owned:
            previous.append(installation_leaf(held[row['parent']][0], row, True))
        else:
            rollback_absent(held[row['parent']][0], row['leaf'])
            previous.append(None)
    return owned, recorded, previous


def rollback_unlink(parent, leaf, before):
    # No name is removed without a complete owned-byte read and current identity.
    if deployment_identity(dep_os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != deployment_identity(before):
        raise ValueError('owned rollback leaf changed before retirement')
    dep_os.unlink(leaf, dir_fd=parent)
    rollback_absent(parent, leaf)
    dep_os.fsync(parent)


def rollback_marker_sync(state, marker):
    before, _ = publication_file(state, 'rollback.json', marker)
    fd = dep_os.open('rollback.json', DEP_OPEN, dir_fd=state)
    try:
        if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
            raise ValueError('rollback marker changed before synchronization')
        dep_os.fsync(fd)
    finally:
        dep_os.close(fd)
    dep_os.fsync(state)
    publication_file(state, 'rollback.json', marker)


def application_rollback(data, ssh_producer):
    # Deliberately disconnected from actual CLI/dispatcher/defaults.
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('application-file rollback requires root')
    digest, owner, rows, marker = application_rollback_plan(data, ssh_producer)
    removed = 0
    with dep_context.ExitStack() as stack:
        held, links = installation_directories(stack)
        state = held[APP_INSTALL_STATE][0]
        rollback_admission(state, held, owner, rows, marker)
        installation_context(held, links)
        lock = dep_os.open('.installer.lock', DEP_OPEN, dir_fd=state)
        stack.callback(dep_os.close, lock)
        initial_lock = dep_os.fstat(lock)
        if deployment_identity(initial_lock) != deployment_identity(dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)):
            raise ValueError('rollback installer lock changed')
        pub_fcntl.flock(lock, pub_fcntl.LOCK_EX | pub_fcntl.LOCK_NB)
        owned, recorded, previous = rollback_admission(state, held, owner, rows, marker)
        installation_context(held, links)
        if not recorded:
            # A complete synchronized marker precedes EVERY destination deletion.
            publication_write(state, 'rollback.json', marker)
        # A retained marker can come from an earlier failed file/parent fsync.
        rollback_marker_sync(state, marker)
        for row, old in zip(rows, previous):
            installation_context(held, links)
            if old is not None:
                rollback_unlink(held[row['parent']][0], row['leaf'], old[0])
                removed += 1
        # Preserve installation ownership until every target parent is synchronized.
        for row in rows:
            parent = held[row['parent']][0]
            rollback_absent(parent, row['leaf'])
            dep_os.fsync(parent)
        if owned:
            before, _ = publication_file(state, 'installation.json', owner)
            installation_context(held, links)
            rollback_unlink(state, 'installation.json', before)
        rollback_marker_sync(state, marker)
        for row in rows:
            rollback_absent(held[row['parent']][0], row['leaf'])
        rollback_absent(state, 'installation.json')
        if publication_entries(state) != {'.installer.lock', 'rollback.json'}:
            raise ValueError('final rollback-state entries mismatch')
        dep_os.fsync(state)
        for current in (dep_os.fstat(lock), dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)):
            if deployment_identity(current) != deployment_identity(initial_lock):
                raise ValueError('rollback lock identity changed')
        installation_context(held, links)
    return {'scope': 'OWNED FIRST-INSTALLATION FILES TO ABSENCE ONLY',
            'publication_sha256': digest, 'rollback_record_sha256': dep_hash.sha256(marker).hexdigest(),
            'files': len(rows), 'removed_files': removed,
            'disposition': 'rolled-back' if owned else 'already-absent',
            'checked_closes_completed': True, 'file_and_directory_fsync_returned': True,
            'authority': {name: False for name in APP_ROLLBACK_AUTHORITY},
            'limits': ['No CLI/default calls this library. Actual stopped-manager/process admission, operational authority and native/full-lifecycle rollback remain required.',
                       'Only exact first-installation file absence is restored; no previous file versions, configuration, accounts, application state or database are restored.',
                       'Foreign/changed ownership, marker, plan or any late payload refuses before deletion. Complete rollback marker is retained for interrupted and idempotent retries.',
                       'The retained marker makes the unchanged installation engine refuse reinstallation. A future separately reviewed transition is required.',
                       'Retirement is sequential/non-set-atomic; failures may leave absent names without success. Open files or loaded manager/process state may outlive unlink. No ABA/concurrent-root or power-loss guarantee.']}

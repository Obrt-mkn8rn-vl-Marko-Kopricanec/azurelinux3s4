"""Checked owned-file reinstallation; disconnected from CLI and defaults.

Only exact rollback-to-installation file state is transitioned. Service/process,
configuration/database and operational lifecycle admission remain prerequisites.
"""


APP_REINSTALL_AUTHORITY = ('operationally_authorized', 'release_authenticated',
                          'configuration_authenticated', 'prior_rollback_proven',
                          'service_stopped', 'manager_state_admitted',
                          'service_started', 'application_healthy',
                          'boot_lifecycle_proven', 'physical_power_loss_proven',
                          'concurrent_root_safety', 'server_ready')


def reinstallation_admission(state, held, owner, rows, marker, configuration=False):
    entries = publication_entries(state)
    if not entries <= {'.installer.lock', 'installation.json', 'rollback.json'}:
        raise ValueError('foreign reinstallation-state entries')
    publication_file(state, '.installer.lock', CONFIG_INSTALL_LOCK if configuration else APP_INSTALL_LOCK)
    owned = publication_file(state, 'installation.json', owner)[0] if 'installation.json' in entries else None
    recorded = publication_file(state, 'rollback.json', marker)[0] if 'rollback.json' in entries else None
    if owned is None and recorded is None:
        raise ValueError('exact rollback or installation ownership required')
    for row in rows:
        if recorded is not None:
            # A marker may represent incomplete rollback: every target must be absent.
            rollback_absent(held[row['parent']][0], row['leaf'])
        else:
            if configuration:
                installation_leaf(held[row['parent']][0], row, True, private_prefix=True)
            else:
                installation_leaf(held[row['parent']][0], row, True)
    return owned, recorded


def reinstallation_owner_sync(state, owner):
    before, _ = publication_file(state, 'installation.json', owner)
    fd = dep_os.open('installation.json', DEP_OPEN, dir_fd=state)
    try:
        if deployment_identity(dep_os.fstat(fd)) != deployment_identity(before):
            raise ValueError('reinstallation owner changed before synchronization')
        dep_os.fsync(fd)
    finally:
        dep_os.close(fd)
    dep_os.fsync(state)
    current, _ = publication_file(state, 'installation.json', owner)
    if deployment_identity(current) != deployment_identity(before):
        raise ValueError('reinstallation owner changed after synchronization')


def reinstallation_apply(data, ssh_producer, configuration=False):
    # No operational dispatcher/default reaches this write-capable library.
    if type(configuration) is not bool:
        raise ValueError('fixed reinstallation kind required')
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('application-file reinstallation requires root')
    digest, owner, rows, marker = (configuration_rollback_plan(data, ssh_producer) if configuration
                                  else application_rollback_plan(data, ssh_producer))
    recorded = None
    with dep_context.ExitStack() as stack:
        held, links = (installation_directories(stack, CONFIG_INSTALL_DIRECTORIES) if configuration
                       else installation_directories(stack))
        state = held[CONFIG_INSTALL_STATE if configuration else APP_INSTALL_STATE][0]
        def check_context():
            if configuration:
                installation_context(held, links, CONFIG_INSTALL_DIRECTORIES)
            else:
                installation_context(held, links)
        def admit():
            return (reinstallation_admission(state, held, owner, rows, marker, configuration=True) if configuration
                    else reinstallation_admission(state, held, owner, rows, marker))
        before = admit()
        check_context()
        lock = dep_os.open('.installer.lock', DEP_OPEN, dir_fd=state)
        stack.callback(dep_os.close, lock)
        initial_lock = dep_os.fstat(lock)
        if deployment_identity(initial_lock) != deployment_identity(dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)):
            raise ValueError('reinstallation installer lock changed')
        pub_fcntl.flock(lock, pub_fcntl.LOCK_EX | pub_fcntl.LOCK_NB)
        owned, recorded = admit()
        if tuple(None if row is None else deployment_identity(row) for row in (owned, recorded)) != tuple(
                None if row is None else deployment_identity(row) for row in before):
            raise ValueError('reinstallation records changed before lock')
        check_context()
        if recorded is not None:
            # Synchronize absence before handing ownership back to the installer.
            for parent in dict.fromkeys(row['parent'] for row in rows):
                dep_os.fsync(held[parent][0])
            for row in rows:
                rollback_absent(held[row['parent']][0], row['leaf'])
            check_context()
            if owned is None:
                publication_write(state, 'installation.json', owner)
            # Complete synchronized ownership survives interrupted marker retirement.
            reinstallation_owner_sync(state, owner)
            admit()
            check_context()
            rollback_unlink(state, 'rollback.json', recorded)
        else:
            # A previous marker unlink can precede a failed parent sync or writer.
            reinstallation_owner_sync(state, owner)
        rollback_absent(state, 'rollback.json')
        publication_file(state, 'installation.json', owner)
        if publication_entries(state) != {'.installer.lock', 'installation.json'}:
            raise ValueError('final reinstallation-state entries mismatch')
        dep_os.fsync(state)
        for current in (dep_os.fstat(lock), dep_os.stat('.installer.lock', dir_fd=state, follow_symlinks=False)):
            if deployment_identity(current) != deployment_identity(initial_lock):
                raise ValueError('reinstallation lock identity changed')
        check_context()
    # Close/unlock before the unchanged installer acquires this SAME lock again.
    # Its fresh complete plan must still match the retained exact ownership bytes.
    installed = (configuration_installation(data, ssh_producer) if configuration
                 else application_installation(data, ssh_producer))
    if (installed['publication_sha256'] != digest
            or installed['installation_record_sha256'] != dep_hash.sha256(owner).hexdigest()):
        raise ValueError('reinstallation writer plan changed')
    return {'scope': 'EXACT OWNED CONFIGURATION FILES ONLY; NO ACTIVATION' if configuration else 'EXACT OWNED APPLICATION FILES ONLY; NO ACTIVATION',
            'publication_sha256': digest,
            'rollback_marker_observed': recorded is not None,
            'disposition': 'rollback-marker-retired' if recorded is not None else 'owned-installation-resumed',
            'installation': installed, 'checked_closes_completed': True,
            'authority': {name: False for name in APP_REINSTALL_AUTHORITY},
            'limits': CONFIG_REINSTALL_LIMITS if configuration else ['No CLI/default invokes this library. Operational, stopped-manager, native and full application lifecycle admission remain required.',
                       'Exact rollback marker requires every selected target absent. Both complete records can resume a file transition; no claim of an observed prior service rollback follows.',
                       'Ownership is synchronized before marker retirement. Partial ownership refuses; failures can leave both records, only ownership, or installed prefixes without success.',
                       'The unchanged installer freshly rebuilds its complete raw plan after transition lock release. Changed sources/state refuse; this gap is not an atomic transaction or concurrent-root/ABA guarantee.',
                       'Only this exact file set is reinstalled. No old versions, accounts, configuration, database or manager state is restored; no physical power-loss or blocked-I/O progress guarantee.']}


def application_reinstallation(data, ssh_producer):
    return reinstallation_apply(data, ssh_producer)

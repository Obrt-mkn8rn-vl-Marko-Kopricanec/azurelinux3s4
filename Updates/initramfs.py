"""Conditional existing-initramfs metadata forecast; never read image contents."""


def initramfs_metadata(observed):
    return (*identity(observed), observed.st_nlink, observed.st_size,
            observed.st_blocks, observed.st_mtime_ns, observed.st_ctime_ns)


def initramfs_scan(directory):
    before = os.fstat(directory)
    trusted(before)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError('initramfs observation requires a protected directory')
    rows, count, total = [], 0, 0
    # scandir is incremental: bound all entries before selecting image names.
    # Do not use cached DirEntry metadata or open image contents.
    with os.scandir(directory) as entries:
        for entry in entries:
            count += 1
            if count > 4096:
                raise ValueError('initramfs directory entry count exceeds its bound')
            name = entry.name
            if not (name.startswith('initramfs-') and name.endswith('.img')):
                continue
            if not re.fullmatch(r'initramfs-[A-Za-z0-9][A-Za-z0-9._+~\-]{0,199}\.img', name):
                raise ValueError('initramfs image name is outside the supported ASCII profile')
            observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
            trusted(observed)
            if (not stat.S_ISREG(observed.st_mode) or observed.st_mode & 0o7000
                    or observed.st_nlink != 1 or not 0 < observed.st_size <= 2 * 1024 ** 3
                    or observed.st_blocks < 0 or observed.st_blocks * 512 > 2 * 1024 ** 3):
                raise ValueError('initramfs image is not a bounded ordinary single-linked file')
            descriptor = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                if (initramfs_metadata(os.fstat(descriptor)) != initramfs_metadata(observed)
                        or mount_id(descriptor) != mount_id(directory)
                        or initramfs_metadata(os.stat(name, dir_fd=directory, follow_symlinks=False))
                           != initramfs_metadata(observed)
                        or initramfs_metadata(os.fstat(descriptor)) != initramfs_metadata(observed)):
                    raise ValueError('initramfs image changed or crosses a mount')
            finally:
                os.close(descriptor)
            basis = max(observed.st_size, observed.st_blocks * 512)
            total += basis
            if len(rows) >= 128 or total > 16 * 1024 ** 3:
                raise ValueError('initramfs image count or allocation exceeds its bound')
            rows.append({'path': '/boot/' + name, 'metadata': list(initramfs_metadata(observed)),
                         'logical_bytes': observed.st_size, 'allocated_bytes': observed.st_blocks * 512,
                         'forecast_basis_bytes': basis})
    if initramfs_metadata(os.fstat(directory)) != initramfs_metadata(before):
        raise ValueError('initramfs directory changed during observation')
    return {'directory_metadata': list(initramfs_metadata(before)),
            'entries': sorted(rows, key=lambda row: row['path'])}


def initramfs_budget(observation=None):
    rows = observation['entries'] if observation is not None else []
    return {
        'schema': 1, 'observation_performed': observation is not None, 'images': rows,
        'observation_sha256': hashlib.sha256(json.dumps(observation, sort_keys=True,
            separators=(',', ':')).encode('ascii')).hexdigest() if observation is not None else None,
        'minimum_work_bytes': sum(128 * 1024 ** 2 + 2 * row['forecast_basis_bytes'] for row in rows),
        'minimum_work_inodes': 8 * len(rows),
        'policy': 'supplemental 128MiB plus twice max(logical bytes, allocated 512-byte blocks) and eight inodes per observed image',
        'scope': 'direct supported /boot/initramfs-*.img metadata ONLY, conditional on incoming named kernel-image declarations; no content read or trigger selection',
        **{key: False for key in ('image_contents_read', 'images_authenticated',
            'all_installed_kernels_accounted', 'regeneration_selection_complete', 'generated_image_size_bounded',
            'space_reserved', 'complete_boot_capacity_checked', 'rollback_capacity_checked',
            'installation_authorized', 'reboot_authorized', 'server_ready')},
    }

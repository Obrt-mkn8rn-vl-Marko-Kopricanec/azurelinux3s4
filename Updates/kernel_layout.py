"""Version/release-bound declared kernel image and module alias; no boot policy."""


KERNEL_LAYOUT_NAMES = frozenset(('kernel', 'kernel-64k', 'kernel-hwe',
                               'kernel-mshv', 'kernel-uvm', 'kernel-uki'))
KERNEL_LAYOUT_PROFILES = {'kernel': ('x86_64', 'aarch64'), 'kernel-hwe': ('x86_64', 'aarch64'),
                          'kernel-64k': ('aarch64',)}


def kernel_layout(proof):
    # The actual shipped hook always performs accepted namespace/lookup
    # correspondence first on the same privately captured current TEST proof.
    proof = interpreter_paths(proof)
    source = proof['namespace_inventory']
    matches, paths = [], set()
    for owner in source['incoming']:
        name = owner['name']
        if name not in KERNEL_LAYOUT_NAMES:
            continue
        architectures = KERNEL_LAYOUT_PROFILES.get(name)
        if architectures is None:
            raise ValueError('kernel declaration layout has not been vetted for this family')
        identity = re.fullmatch(re.escape(name) +
            r'-(?:(0|[1-9][0-9]{0,9}):)?([A-Za-z0-9._+~^]+)-([A-Za-z0-9._+~^]+)\.(x86_64|aarch64|noarch)',
            owner['nevra'])
        if (identity is None or int(identity[1] or '0') > 2**32 - 1
                or identity[4] not in architectures):
            raise ValueError('kernel declaration identity/architecture is unsupported')
        release = identity[2] + '-' + identity[3]
        image = '/boot/vmlinuz-' + release
        alias = '/lib/modules/' + release + '/vmlinuz'
        entries = {row['path']: row for row in owner['files']}
        regular, link = entries.get(image), entries.get(alias)
        if (regular is None or not stat.S_ISREG(regular['mode']) or regular['mode'] & 0o7022
                or regular['bytes'] == 0 or regular['flags'] & 64
                or link is None or not stat.S_ISLNK(link['mode']) or link['flags'] & 64
                or link['link'] != image):
            raise ValueError('kernel image/module alias declarations are missing or inconsistent')
        # Check every direct versioned image/module-alias declaration in this
        # header, not just the first expected pair. Other files are unselected.
        for row in owner['files']:
            if (row['path'].startswith('/boot/vmlinuz-') and row['path'] != image
                    or re.fullmatch(r'/lib/modules/[^/]+/vmlinuz', row['path']) and row['path'] != alias):
                raise ValueError('kernel header declares another image/module release')
        if image in paths or alias in paths:
            raise ValueError('incoming kernel declarations share an image/module alias')
        paths.update((image, alias))
        matches.append({'owner': {key: owner[key] for key in (
            'name', 'nevra', 'header_bytes', 'header_sha256', 'file', 'sha256', 'bytes')},
            'architecture': identity[4], 'epoch': identity[1] or '0',
            'declared_release': release, 'image': regular, 'module_alias': link})
    proof['kernel_layout'] = {
        'schema': 1, 'matches': matches, 'kernel_headers_checked': len(matches),
        'declared_pairs_consistent': bool(matches),
        'namespace_inventory_sha256': proof['interpreter_path_correspondence']['inventory_sha256'],
        'scope': 'incoming kernel/kernel-hwe/kernel-64k declared image and module alias ONLY',
        **{key: False for key in ('all_kernel_families_supported', 'all_boot_artifacts_checked',
            'payload_bytes_read', 'image_format_checked', 'hmac_verified', 'modules_complete',
            'installed_baseline_authenticated', 'running_kernel_identified', 'bootloader_checked',
            'initramfs_checked', 'kernel_retention_policy_satisfied', 'rollback_policy_satisfied',
            'bootability_proven', 'reboot_authorized', 'kernel_version_policy_satisfied',
            'installation_authorized', 'installs_performed', 'scripts_executed', 'server_ready')},
    }
    return proof

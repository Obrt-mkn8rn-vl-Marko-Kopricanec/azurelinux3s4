"""Expected kernel path reuse from current identities; no filesystem/boot proof."""


KERNEL_PATH_ARCHITECTURES = {'kernel': ('x86_64', 'aarch64'), 'kernel-hwe': ('x86_64', 'aarch64'),
                             'kernel-64k': ('aarch64',)}


def kernel_expected_paths(owner):
    name, architecture = package(owner)
    if architecture not in KERNEL_PATH_ARCHITECTURES.get(name, ()):
        raise ValueError('kernel expected path identity/family/architecture is unvetted')
    epoch, version, release = version_evr(name, owner['nevra'], architecture)
    suffix = version + '-' + release
    return ('/boot/vmlinuz-' + suffix, '/lib/modules/' + suffix + '/vmlinuz'), epoch


def kernel_paths(proof, comparator_factory=version_native):
    # Accepted current correspondence/version/floor guards bind and validate
    # the complete inventory first. No independently authenticated baseline is
    # inferred, and no namespace or filesystem observation is substituted.
    proof = floor_observe(proof, comparator_factory)
    incoming = [entry for entry in proof['effects']['incoming'] if entry['name'] in KERNELS]
    installed, occupied, claimed = [], set(), set()
    if incoming:
        for entry in proof['effects']['installed_versions']['entries']:
            if entry['name'] in KERNELS:
                paths, _ = kernel_expected_paths(entry)
                occupied.update(paths)
                installed.append(entry)
    matches = []
    for entry in incoming:
        paths, epoch = kernel_expected_paths(entry)
        if occupied.intersection(paths):
            raise ValueError('kernel expected image/module paths overlap an observed installed identity')
        if claimed.intersection(paths):
            raise ValueError('incoming kernel identities share expected image/module paths')
        claimed.update(paths)
        matches.append({'owner': {key: entry[key] for key in (
            'name', 'nevra', 'header_bytes', 'header_sha256', 'file', 'sha256', 'bytes')},
            'epoch': epoch, 'expected_paths': list(paths)})
    proof['kernel_path_guard'] = {
        'schema': 1, 'matches': matches, 'incoming_kernel_count': len(incoming),
        'observed_kernel_identities_considered': len(installed),
        'expected_path_comparison_performed': bool(incoming), 'expected_paths_disjoint': bool(incoming),
        'baseline_sha256': proof['baseline']['sha256'],
        'installed_inventory_sha256': proof['effects']['installed_versions']['entries_sha256'],
        'scope': 'version-release expected paths from current known kernel identities ONLY; epoch omitted',
        **{key: False for key in ('installed_headers_authenticated', 'actual_filesystem_collisions_checked',
            'installed_declared_paths_read', 'incoming_declared_paths_read', 'all_kernel_names_identified',
            'all_kernel_families_supported', 'alternate_paths_checked', 'aliases_hardlinks_checked',
            'kernel_retention_policy_satisfied', 'rollback_policy_satisfied', 'running_kernel_identified',
            'bootability_proven', 'installation_authorized', 'installs_performed', 'scripts_executed',
            'reboot_authorized', 'server_ready')},
    }
    return proof

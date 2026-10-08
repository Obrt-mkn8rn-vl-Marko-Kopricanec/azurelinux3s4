"""Supplemental minimum boot-work allowance, not generated-image capacity proof."""


def boot_work_budget(files):
    images, declarations = {}, []
    for entry in files:
        if not re.fullmatch(r'/boot/vmlinuz-[^/]+', entry['path']) or entry['flags'] & 64:
            continue
        if not stat.S_ISREG(entry['mode']) or entry['bytes'] == 0:
            raise ValueError('boot-work image declaration is not a nonempty ordinary file')
        images[entry['path']] = max(images.get(entry['path'], 0), entry['bytes'])
        declarations.append(entry)
        if len(images) > 128:
            raise ValueError('boot-work image count exceeds its bound')
    # This repository floor supplements existing gross payload/db/headroom
    # accounting. It does NOT upper-bound dracut, triggers or rollback work.
    required = sum(128 * 1024 * 1024 + 4 * size for size in images.values())
    return {
        'schema': 1, 'images': [{'path': path, 'declared_bytes': size} for path, size in sorted(images.items())],
        'source_sha256': hashlib.sha256(json.dumps(declarations, sort_keys=True,
            separators=(',', ':')).encode('utf-8')).hexdigest(),
        'minimum_work_bytes': required, 'minimum_work_inodes': 8 * len(images),
        'policy': 'supplemental 128MiB plus four declared image lengths and eight inodes per unique named image',
        'scope': 'nonghost ordinary /boot/vmlinuz-* declarations ONLY; no kernel owner/trigger selection',
        **{key: False for key in ('kernel_owner_authenticated', 'all_regeneration_triggers_accounted',
            'generated_image_size_bounded', 'space_reserved', 'complete_boot_capacity_checked',
            'rollback_capacity_checked', 'installation_authorized', 'reboot_authorized', 'server_ready')},
    }

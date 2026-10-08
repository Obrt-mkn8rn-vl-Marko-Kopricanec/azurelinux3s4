"""Current incoming EVR floors against observed installed headers; no install policy."""


FLOOR_FIELDS = frozenset(('instance', 'name', 'nevra', 'header_bytes', 'header_sha256'))
FLOOR_LIMIT = 8 * 1024 * 1024


def floor_inventory(proof):
    baseline = proof['baseline']
    source = proof['effects']['installed_versions']
    if (not isinstance(source, dict) or type(source.get('schema')) is not int or source['schema'] != 1
            or source.get('complete_observed_header_inventory') is not True
            or any(source.get(flag) is not False for flag in (
                'installed_headers_authenticated', 'identity_fields_independently_authenticated', 'snapshot_atomic',
                'all_incoming_versions_checked', 'kernel_version_policy_satisfied', 'freshness_proven',
                'anti_rollback_proven', 'installation_authorized', 'server_ready'))
            or not isinstance(source.get('entries'), list)
            or number(source['headers'], 1, 32768) != baseline['headers']
            or len(source['entries']) != source['headers']):
        raise ValueError('incoming floor lacks the complete qualified installed inventory')
    entries, instances, last = source['entries'], {}, 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != FLOOR_FIELDS:
            raise ValueError('incoming floor installed record is unsupported')
        instance = number(entry['instance'], 1, 2**32 - 1)
        if (instance <= last or not isinstance(entry['name'], str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', entry['name'])
                or not isinstance(entry['nevra'], str) or not 0 < len(entry['nevra']) <= 1024
                or not entry['nevra'].startswith(entry['name'] + '-')
                or any(ord(value) < 33 or ord(value) > 126 for value in entry['nevra'])):
            raise ValueError('incoming floor installed identity/order is unsupported')
        number(entry['header_bytes'], 8, 8 * 1024 * 1024); digest(entry['header_sha256'])
        last = instance; instances[instance] = entry
    material = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode('ascii')
    if (not 0 < len(material) <= FLOOR_LIMIT
            or number(source['entries_bytes'], 1, FLOOR_LIMIT) != len(material)
            or digest(source['entries_sha256']) != hashlib.sha256(material).hexdigest()):
        raise ValueError('incoming floor inventory serialization is inconsistent')
    observed = hashlib.sha256(json.dumps([(entry['instance'], entry['header_sha256']) for entry in entries],
                                        separators=(',', ':')).encode()).hexdigest()
    if digest(source['baseline_sha256']) != observed or observed != baseline['sha256']:
        raise ValueError('incoming floor inventory differs from the current baseline')
    for removed in proof['effects']['removals']:
        if instances.get(removed['instance']) != {name: removed[name] for name in FLOOR_FIELDS}:
            raise ValueError('incoming floor removal differs from its installed record')
    return entries


def floor_observe(proof, comparator_factory=version_native):
    if proof['replacement_version_guard'].get('native_ordering_controls_passed') is not True:
        raise ValueError('incoming floor requires the current replacement version guard')
    entries = floor_inventory(proof)
    incoming = proof['effects']['incoming']
    # The unchanged correspondence guard has already bound additions and
    # limited incoming to one snapshot per name/architecture, at most128.
    parsed = [(value, package(value), version_evr(value['name'], value['nevra'], package(value)[1]))
              for value in incoming]
    names = {key[0] for _, key, _ in parsed}
    groups = {}
    for entry in entries:
        if entry['name'] in names:
            key = package(entry)
            groups.setdefault(key, []).append((entry, version_evr(entry['name'], entry['nevra'], key[1])))
    compare = comparator_factory()
    calls = 0
    def checked(left, right):
        nonlocal calls
        calls += 1
        if calls > 36 + 6 * 32768:
            raise ValueError('incoming floor comparison count exceeds its bound')
        result = compare(left, right)
        if type(result) is not int or result not in (-1, 0, 1):
            raise ValueError('incoming floor native result is unsupported')
        return result
    controls = []
    for left, right, expected in VERSION_PROBES:
        observed = [checked(left, right), checked(right, left), checked(left, left), checked(right, right)]
        if observed != [expected, -expected, 0, 0]:
            raise ValueError('incoming floor native participation failed')
        controls.append({'left': left, 'right': right, 'observed': observed})
    def ordering(left, right):
        decisions = []
        for label, first, second in zip(('epoch', 'version', 'release'), left, right):
            forward, reverse = checked(first, second), checked(second, first)
            if reverse != -forward:
                raise ValueError('incoming floor native order is not reversible')
            decisions.append({'component': label, 'left': first, 'right': second, 'result': forward})
            if forward: break
        return decisions[-1]['result'], decisions
    matches, absent, kernel_matches = [], [], 0
    for value, key, evr in parsed:
        if any(other[0] == key[0] and other[1] != key[1] for other in groups):
            raise ValueError('incoming floor same-name architecture conflict')
        candidates = groups.get(key, [])
        binding = {name: value[name] for name in ('name', 'nevra', 'file', 'sha256', 'bytes', 'header_sha256')}
        binding['architecture'] = key[1]
        if not candidates:
            absent.append(binding)
            continue
        maximum, maximum_evr = candidates[0]
        for candidate, candidate_evr in candidates[1:]:
            result, _ = ordering(candidate_evr, maximum_evr)
            if result > 0: maximum, maximum_evr = candidate, candidate_evr
        result, decisions = ordering(evr, maximum_evr)
        if result != 1:
            raise ValueError('incoming floor is a downgrade or version-equivalent reinstall')
        kernel_matches += key[0] in KERNELS
        matches.append({**binding, 'installed_instances_considered': len(candidates),
                        'maximum_installed': maximum, 'maximum_evr': list(maximum_evr),
                        'incoming_evr': list(evr), 'comparisons': decisions})
    proof['incoming_version_guard'] = {
        'schema': 1, 'matches': matches, 'without_installed_name': absent,
        'incoming_count': len(incoming), 'matched_incoming_count': len(matches),
        'observed_installed_headers': len(entries), 'inventory_sha256': proof['effects']['installed_versions']['entries_sha256'],
        'baseline_sha256': proof['baseline']['sha256'], 'ordering_controls': controls, 'native_calls': calls,
        'all_current_incoming_identities_evaluated': bool(incoming),
        'matched_incoming_strictly_newer': bool(matches), 'matched_kernel_floors': kernel_matches,
        'scope': 'current same-name/architecture observed native EVR maximum; new names have NO installed floor',
        **{name: False for name in ('installed_baseline_authenticated', 'native_library_identity_authenticated',
            'kernel_version_policy_satisfied', 'package_continuity_proven', 'freshness_proven', 'anti_rollback_proven',
            'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized',
            'installs_performed', 'scripts_executed', 'server_ready')},
    }
    return proof

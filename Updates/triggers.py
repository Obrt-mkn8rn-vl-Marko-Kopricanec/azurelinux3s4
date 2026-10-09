"""Declared trigger-array correspondence only; no condition or script evaluation."""

import os
from pathlib import Path
import resource
import stat
import sys


TRIGGER_ARRAYS = (
    ('trigger', 1065, 1092, 5027, 1066, 1067, 1068, 1069, None),
    ('filetrigger', 5066, 5067, 5068, 5069, 5071, 5072, 5070, 5084),
    ('transfiletrigger', 5076, 5077, 5078, 5079, 5081, 5082, 5080, 5085),
)
TRIGGER_PHASES = (1 << 16, 1 << 17, 1 << 18, 1 << 25)
TRIGGER_LIMIT = 32 * 1024 * 1024


def trigger_number(value, minimum=0, maximum=2**32 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('trigger observation integer is outside its bound')
    return value


def trigger_hash(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('trigger observation digest is malformed')
    return value


def trigger_tags(owner):
    tags, previous = {}, 0
    if not isinstance(owner['tags'], list) or len(owner['tags']) > 44:
        raise ValueError('trigger owner tag list exceeds its bound')
    for entry in owner['tags']:
        if not isinstance(entry, dict) or set(entry) != {'tag', 'name', 'type', 'count', 'bytes', 'sha256', 'values'}:
            raise ValueError('trigger owner tag record is unsupported')
        tag = trigger_number(entry['tag'], 1)
        if tag <= previous or tag not in EFFECT_TAGS:
            raise ValueError('trigger owner tags are duplicated, unordered or unknown')
        previous = tag
        label, kind, disclosed = EFFECT_TAGS[tag]
        count = trigger_number(entry['count'], 1, 4096)
        legacy = tag in (1085, 1086, 1087, 1088, 1091, 1153, 1154) and entry['type'] == 6 and count == 1
        if (type(entry['type']) is not int or (entry['type'] != kind and not legacy)
                or entry['name'] != label or not isinstance(entry['values'], list) or len(entry['values']) != count):
            raise ValueError('trigger owner tag type/count/label is inconsistent')
        size, encoded = 0, bytearray()
        for value in entry['values']:
            if kind == 4:
                encoded.extend(struct.pack('>I', trigger_number(value)))
                size += 4
            elif disclosed:
                if not isinstance(value, str) or '\0' in value or len(value.encode('utf-8')) > 4096:
                    raise ValueError('trigger program declaration is unsupported')
                raw = value.encode('utf-8') + b'\0'
                encoded.extend(raw); size += len(raw)
            else:
                if not isinstance(value, dict) or set(value) != {'bytes', 'sha256'}:
                    raise ValueError('trigger opaque declaration is unsupported')
                size += trigger_number(value['bytes'], 0, 1024 * 1024) + 1
                trigger_hash(value['sha256'])
        if trigger_number(entry['bytes'], 1, 8 * 1024 * 1024) != size:
            raise ValueError('trigger tag encoded length is inconsistent')
        trigger_hash(entry['sha256'])
        if (kind == 4 or disclosed) and hashlib.sha256(encoded).hexdigest() != entry['sha256']:
            raise ValueError('trigger disclosed tag digest is inconsistent')
        tags[tag] = entry
    return tags


def trigger_groups(owner):
    tags, families = trigger_tags(owner), []
    for family, bodies, programs, flags, names, versions, senses, indexes, priorities in TRIGGER_ARRAYS:
        identifiers = (bodies, programs, flags, names, versions, senses, indexes, priorities)
        if not any(tag in tags for tag in identifiers if tag is not None):
            continue
        required = (bodies, programs, names, versions, senses, indexes) + ((priorities,) if priorities else ())
        if any(tag not in tags for tag in required):
            raise ValueError('trigger family has incomplete declared arrays: ' + family)
        scripts, conditions = tags[bodies]['count'], tags[names]['count']
        if (tags[programs]['count'] != scripts or any(tags[tag]['count'] != conditions for tag in (versions, senses, indexes))
                or flags in tags and tags[flags]['count'] != scripts
                or priorities and tags[priorities]['count'] != scripts):
            raise ValueError('trigger family array counts do not correspond: ' + family)
        if any(not value for value in tags[programs]['values']) or any(not value['bytes'] for value in tags[names]['values']):
            raise ValueError('trigger program or condition name is empty')
        positions = [[] for _ in range(scripts)]
        for position, index in enumerate(tags[indexes]['values']):
            if not 0 <= index < scripts:
                raise ValueError('trigger condition index is outside the declared script array')
            positions[index].append(position)
        slots = []
        for index, references in enumerate(positions):
            if not references:
                raise ValueError('trigger script slot has no declared condition')
            phase_masks = {tags[senses]['values'][position] & sum(TRIGGER_PHASES) for position in references}
            if (len(phase_masks) != 1 or next(iter(phase_masks)) not in TRIGGER_PHASES
                    or family != 'trigger' and next(iter(phase_masks)) == 1 << 25):
                raise ValueError('trigger script conditions have inconsistent or unsupported declared phases')
            slots.append({'script_index': index, 'condition_positions': references,
                'declared_phase_mask': next(iter(phase_masks)),
                'script_flags': tags[flags]['values'][index] if flags in tags else None,
                'priority': tags[priorities]['values'][index] if priorities else None})
        families.append({'family': family, 'scripts': scripts, 'conditions': conditions, 'slots': slots,
            'source_tags': [tag for tag in identifiers if tag in tags]})
    return families


def trigger_observe(proof):
    if (type(proof['schema']) is not int or proof['schema'] != 1 or proof.get('test_passed') is not True
            or any(proof.get(flag) is not False for flag in ('installs_performed', 'scripts_executed',
                'installation_authorized', 'storage_capacity_checked', 'freshness_proven'))):
        raise ValueError('trigger inputs require the current qualified effects TEST')
    audit, source = proof['effects'], proof['effects']['installed_versions']
    if (type(audit['schema']) is not int or audit['schema'] != 1
            or audit.get('script_metadata_observed') is not True or audit.get('removals_bound_to_installed_instances') is not True
            or any(audit.get(flag) is not False for flag in ('installed_headers_authenticated', 'trigger_selection_complete',
                'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied', 'rollback_policy_satisfied'))
            or type(source['schema']) is not int or source['schema'] != 1
            or type(source['headers']) is not int or type(source['entries_bytes']) is not int
            or source.get('complete_observed_header_inventory') is not True
            or any(source.get(flag) is not False for flag in ('installed_headers_authenticated',
                'identity_fields_independently_authenticated', 'snapshot_atomic', 'all_incoming_versions_checked',
                'kernel_version_policy_satisfied', 'freshness_proven', 'anti_rollback_proven', 'installation_authorized', 'server_ready'))
            or not isinstance(source['entries'], list) or not 1 <= len(source['entries']) <= 32768):
        raise ValueError('trigger inputs lack the qualified installed/script inventory')
    instances = {entry['instance']: entry for entry in source['entries']}
    if (len(instances) != len(source['entries']) or list(instances) != sorted(instances)
            or any(set(entry) != set(INSTALLED_VERSION_FIELDS) for entry in source['entries'])
            or source != installed_version_inventory(instances, proof['baseline'])
            or type(audit['installed_headers_observed']) is not int or audit['installed_headers_observed'] != len(instances)):
        raise ValueError('trigger installed inventory differs from its complete baseline')
    incoming, installed, removed = audit['incoming'], audit['installed_script_owners'], audit['removals']
    for values, limit in ((incoming, 128), (installed, 32768), (removed, 32768), (proof['additions'], 128), (proof['removals'], 32768)):
        if not isinstance(values, list) or len(values) > limit:
            raise ValueError('trigger owner/plan count exceeds its bound')
    if proof.get('rpm_test_performed') is not bool(proof['additions']):
        raise ValueError('trigger TEST participation differs from the actual batch')
    binding = lambda value: (value['file'], value['sha256'], value['bytes'], value['nevra'])
    if sorted(map(binding, incoming)) != sorted(map(binding, proof['additions'])):
        raise ValueError('trigger incoming owners differ from the current native additions')
    owners, installed_owners, incoming_files, total_slots, total_conditions = [], {}, set(), 0, 0
    for kind, values in (('installed', installed), ('incoming', incoming)):
        for owner in values:
            trigger_number(owner['header_bytes'], 8, 8 * 1024 * 1024); trigger_hash(owner['header_sha256'])
            if (not isinstance(owner['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', owner['name'])
                    or not isinstance(owner['nevra'], str) or not 0 < len(owner['nevra']) <= 1024
                    or not owner['nevra'].startswith(owner['name'] + '-') or any(ord(c) < 33 or ord(c) > 126 for c in owner['nevra'])):
                raise ValueError('trigger owner identity is unsupported')
            if kind == 'installed':
                instance = trigger_number(owner['instance'], 1)
                if (instance in installed_owners or instances.get(instance) != {name: owner[name] for name in INSTALLED_VERSION_FIELDS}
                        or not owner['tags']):
                    raise ValueError('trigger installed owner differs from its observed instance')
                installed_owners[instance] = owner
                identity = {'instance': instance}
            else:
                if not isinstance(owner['file'], str) or not re.fullmatch(r'packages/[0-9]+\.rpm', owner['file']) or owner['file'] in incoming_files:
                    raise ValueError('trigger incoming snapshot is unsupported or duplicated')
                trigger_hash(owner['sha256']); trigger_number(owner['bytes'], 1, 512 * 1024 * 1024)
                incoming_files.add(owner['file'])
                identity = {name: owner[name] for name in ('file', 'sha256', 'bytes')}
            families = trigger_groups(owner)
            total_slots += sum(family['scripts'] for family in families)
            total_conditions += sum(family['conditions'] for family in families)
            if total_slots > 8192 or total_conditions > 65536:
                raise ValueError('trigger correspondence exceeds its aggregate work bound')
            owners.append({'kind': kind, **identity, **{name: owner[name] for name in ('name', 'nevra', 'header_sha256')},
                           'families': families})
    removed_instances = set()
    if [owner['nevra'] for owner in removed] != proof['removals']:
        raise ValueError('trigger removals differ from the current native order')
    for owner in removed:
        instance = trigger_number(owner['instance'], 1)
        if (instance in removed_instances or instances.get(instance) != {name: owner[name] for name in INSTALLED_VERSION_FIELDS}
                or owner['classification'] not in ('same-name-replacement', 'other-removal')
                or owner['tags'] != installed_owners.get(instance, {'tags': []})['tags']):
            raise ValueError('trigger removal differs from the observed installed owner')
        removed_instances.add(instance)
    proof['trigger_input_observation'] = {'schema': 1, 'owners': owners,
        'script_slots': total_slots, 'condition_references': total_conditions,
        'declared_arrays_correspond': bool(total_slots), 'removed_instances': sorted(removed_instances),
        'baseline_sha256': proof['baseline']['sha256'], 'inventory_sha256': source['entries_sha256'],
        'scope': 'declared index/count/phase/priority correspondence ONLY; conditions and bodies remain opaque hashed bytes',
        **{flag: False for flag in ('condition_text_available', 'conditions_evaluated', 'trigger_selection_complete',
            'transaction_file_actions_observed', 'execution_order_complete', 'script_execution_plan_complete',
            'installed_headers_authenticated', 'script_policy_satisfied', 'removal_policy_satisfied',
            'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof


def trigger_private(path):
    before = path.lstat()
    signature = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= TRIGGER_LIMIT):
        raise ValueError('trigger input is not a bounded private regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if signature(os.fstat(stream.fileno())) != signature(before):
            raise ValueError('trigger input changed before reading')
        material = stream.read(TRIGGER_LIMIT + 1)
        if (len(material) != before.st_size or signature(os.fstat(stream.fileno())) != signature(before)
                or signature(path.lstat()) != signature(before)):
            raise ValueError('trigger input changed during reading')
    return material


def trigger_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result: raise ValueError('trigger input JSON contains duplicate keys')
        result[name] = value
    return result


def trigger_main(after=None):
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        material = trigger_private(Path(sys.argv[1]) / 'result.json')
        proof = trigger_observe(json.loads(material, object_pairs_hook=trigger_pairs))
        if after is not None:
            proof = after(proof)
            proof['file_trigger_prefix_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_condition_observation' in proof:
                proof['trigger_condition_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_range_observation' in proof:
                proof['trigger_range_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'provides_observation' in proof:
                proof['provides_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'provider_match_observation' in proof:
                proof['provider_match_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_source_observation' in proof:
                proof['trigger_source_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'header_input_observation' in proof:
                proof['header_input_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'header_match_observation' in proof:
                proof['header_match_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_first_observation' in proof:
                proof['trigger_first_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'header_iteration_observation' in proof:
                proof['header_iteration_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_count_observation' in proof:
                proof['trigger_count_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_argument_observation' in proof:
                proof['trigger_argument_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_iterator_observation' in proof:
                proof['trigger_iterator_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
            if 'trigger_walk_observation' in proof:
                proof['trigger_walk_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        if 'transaction_element_observation' in proof:
            proof['transaction_element_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        if 'psm_goal_observation' in proof:
            proof['psm_goal_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        if 'psm_input_observation' in proof:
            proof['psm_input_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        if 'psm_route_observation' in proof:
            proof['psm_route_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        if 'psm_failure_observation' in proof:
            proof['psm_failure_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        if 'psm_verification_observation' in proof:
            proof['psm_verification_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        proof['trigger_input_observation']['input_sha256'] = hashlib.sha256(material).hexdigest()
        output = json.dumps(proof, sort_keys=True)
        if len(output.encode('utf-8')) > TRIGGER_LIMIT:
            raise ValueError('trigger observation exceeds its complete output bound')
        print(output)
        return 0
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, IndexError, AttributeError, MemoryError) as error:
        print('azurelinux3s4: declared trigger inputs deferred: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(trigger_main())

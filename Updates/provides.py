"""Bind declared Provides arrays to current audited headers; never select providers."""

import hashlib
import json
import re
import struct


PROVIDES_TAGS = (1047, 1112, 1113)
PROVIDES_RECORD_LIMIT = 65536
PROVIDES_BYTES_LIMIT = 8 * 1024 * 1024
provides_projection = False


def provides_export(material, audited):
    # The native producer supplies the SAME export already passed to audit_header.
    if (not 8 <= len(material) <= 8 * 1024 * 1024
            or audited['header_bytes'] != len(material)
            or audited['header_sha256'] != hashlib.sha256(material).hexdigest()):
        raise ValueError('Provides export differs from the audited header')
    entries, size = struct.unpack_from('>II', material)
    start = 8 + 16 * entries
    if not 0 < entries <= 65536 or start + size != len(material):
        raise ValueError('Provides export layout is inconsistent')
    tags = {}
    for index in range(entries):
        tag, kind, offset, count = struct.unpack_from('>IIII', material, 8 + 16 * index)
        if tag not in PROVIDES_TAGS:
            continue
        if (tag in tags or kind != (4 if tag == 1112 else 8)
                or not 1 <= count <= 4096 or offset >= size):
            raise ValueError('Provides export tag type/count/identity is unsupported')
        cursor, values = start + offset, []
        if kind == 4:
            end = cursor + 4 * count
            if offset % 4 or end > len(material):
                raise ValueError('Provides integer array exceeds the header or is unaligned')
            values = list(struct.unpack_from('>' + 'I' * count, material, cursor))
            cursor = end
        else:
            bound = 4096 if tag == 1047 else 1024
            for _ in range(count):
                end = material.find(b'\0', cursor, min(len(material), cursor + bound + 1))
                if end < cursor or tag == 1047 and end == cursor:
                    raise ValueError('Provides string is empty, unterminated or excessive')
                values.append(material[cursor:end].hex())
                cursor = end + 1
        encoded = material[start + offset:cursor]
        tags[tag] = {'tag': tag, 'type': kind, 'count': count, 'bytes': len(encoded),
                     'sha256': hashlib.sha256(encoded).hexdigest(), 'values': values}
    projected = {'schema': 1, 'tags': [tags[tag] for tag in sorted(tags)]}
    # Complete absence is distinct from partial/legacy arrays; never infer EVRs.
    provides_records(projected)
    return projected


def provides_records(projected):
    if (not isinstance(projected, dict) or set(projected) != {'schema', 'tags'}
            or type(projected['schema']) is not int or projected['schema'] != 1
            or not isinstance(projected['tags'], list) or len(projected['tags']) not in (0, 3)):
        raise ValueError('Provides projection is missing or has incomplete arrays')
    if not projected['tags']:
        return []
    tags = {}
    for expected, row in zip(PROVIDES_TAGS, projected['tags']):
        if (not isinstance(row, dict) or set(row) != {'tag', 'type', 'count', 'bytes', 'sha256', 'values'}
                or type(row['tag']) is not int or row['tag'] != expected
                or type(row['type']) is not int or row['type'] != (4 if expected == 1112 else 8)
                or type(row['count']) is not int or not 1 <= row['count'] <= 4096
                or not isinstance(row['values'], list) or len(row['values']) != row['count']):
            raise ValueError('Provides projection tag order/type/count is inconsistent')
        encoded = bytearray()
        for value in row['values']:
            if expected == 1112:
                if type(value) is not int or not 0 <= value <= 2**32 - 1:
                    raise ValueError('Provides flags are outside uint32')
                encoded.extend(struct.pack('>I', value))
            else:
                bound = 4096 if expected == 1047 else 1024
                if (not isinstance(value, str) or len(value) > 2 * bound or len(value) % 2
                        or not re.fullmatch(r'(?:[0-9a-f]{2})*', value)):
                    raise ValueError('Provides string hex encoding is unsupported')
                raw = bytes.fromhex(value)
                if b'\0' in raw or expected == 1047 and not raw:
                    raise ValueError('Provides string contains NUL or an empty name')
                encoded.extend(raw + b'\0')
        if (type(row['bytes']) is not int or row['bytes'] != len(encoded)
                or not isinstance(row['sha256'], str) or row['sha256'] != hashlib.sha256(encoded).hexdigest()):
            raise ValueError('Provides encoded array differs from its commitment')
        tags[expected] = row
    if len({row['count'] for row in tags.values()}) != 1:
        raise ValueError('Provides array counts do not correspond')
    return [{'position': position, 'name_hex': name, 'evr_hex': evr, 'declared_flags': flags}
            for position, (name, flags, evr) in enumerate(zip(
                tags[1047]['values'], tags[1112]['values'], tags[1113]['values']))]


def provides_observe(proof):
    # Fresh accepted guards remain mandatory, including current package-EVR work.
    proof = trigger_range_observe(proof)
    audit = proof['effects']
    inventory = audit['installed_versions']['entries']
    installed = audit['installed_provides']
    fields = (*INSTALLED_VERSION_FIELDS, 'provides')
    if (not isinstance(installed, list) or len(installed) != len(inventory)
            or any(not isinstance(row, dict) or set(row) != set(fields) for row in installed)
            or any(type(row['instance']) is not int for row in installed)
            or [{field: row[field] for field in INSTALLED_VERSION_FIELDS} for row in installed] != inventory):
        raise ValueError('Provides installed projection differs from the complete current inventory')
    by_instance = {row['instance']: row for row in installed}
    for owner in (*audit['installed_script_owners'], *audit['removals']):
        if {field: owner[field] for field in fields} != by_instance.get(owner['instance']):
            raise ValueError('Provides script/removal projection differs from its installed instance')
    owners, count, total = [], 0, 0
    for kind, values in (('installed', installed), ('incoming', audit['incoming'])):
        for owner in values:
            records = provides_records(owner['provides'])
            count += len(records)
            total += sum(len(row['name_hex']) // 2 + len(row['evr_hex']) // 2 + 4 for row in records)
            if count > PROVIDES_RECORD_LIMIT or total > PROVIDES_BYTES_LIMIT:
                raise ValueError('Provides declarations exceed their aggregate observation bound')
            identity = {field: owner[field] for field in (
                ('instance',) if kind == 'installed' else ('file', 'sha256', 'bytes'))}
            owners.append({'kind': kind, **identity,
                **{field: owner[field] for field in ('name', 'nevra', 'header_bytes', 'header_sha256')},
                'source_tags': owner['provides']['tags'], 'provides': records})
    material = json.dumps(owners, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['provides_observation'] = {'schema': 1, 'owners': owners, 'provides': count,
        'declaration_bytes': total, 'owners_bytes': len(material), 'owners_sha256': hashlib.sha256(material).hexdigest(),
        'installed_headers': len(installed), 'incoming_headers': len(audit['incoming']),
        'complete_observed_installed_projection': True, 'declared_provides_observed': bool(count),
        'baseline_sha256': proof['baseline']['sha256'],
        'inventory_sha256': audit['installed_versions']['entries_sha256'],
        'scope': 'ALL current observed installed/incoming header Provides declarations ONLY; bytes/positions are not dependency or trigger matches',
        **{flag: False for flag in ('dependency_names_interpreted', 'provided_evr_ranges_compared',
            'package_trigger_matches_observed', 'transaction_temporal_sources_selected', 'trigger_selection_complete',
            'execution_order_complete', 'script_execution_plan_complete', 'installed_headers_authenticated',
            'native_library_identity_authenticated', 'script_policy_satisfied', 'removal_policy_satisfied',
            'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

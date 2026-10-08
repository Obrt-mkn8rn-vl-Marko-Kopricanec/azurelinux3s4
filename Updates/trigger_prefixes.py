"""Observe literal file-trigger prefixes; never select files or execute scripts."""

import hashlib
import re
import struct


FILE_TRIGGER_PREFIX_TAGS = (5069, 5079)
FILE_TRIGGER_PREFIX_LIMIT = 8 * 1024 * 1024
file_trigger_prefix_projection = False


def file_trigger_export(material, audited):
    # Called with the very same headerExport bytes already admitted by audit_header.
    if (audited['header_bytes'] != len(material)
            or audited['header_sha256'] != hashlib.sha256(material).hexdigest()):
        raise ValueError('file-trigger prefix export differs from the audited header')
    entries, size = struct.unpack_from('>II', material)
    start = 8 + 16 * entries
    if not 0 < entries <= 65536 or start + size != len(material):
        raise ValueError('file-trigger prefix export layout is inconsistent')
    tags = {entry['tag']: entry for entry in audited['tags']}
    result, seen = [], set()
    for index in range(entries):
        tag, kind, offset, count = struct.unpack_from('>IIII', material, 8 + 16 * index)
        if tag not in FILE_TRIGGER_PREFIX_TAGS:
            continue
        source = tags.get(tag)
        if (tag in seen or kind != 8 or not 1 <= count <= 4096 or offset >= size
                or source is None or source['type'] != kind or source['count'] != count):
            raise ValueError('file-trigger prefix export tag is inconsistent')
        seen.add(tag)
        cursor, values = start + offset, []
        for position in range(count):
            end = material.find(b'\0', cursor, min(len(material), cursor + 4097))
            if end < cursor:
                raise ValueError('file-trigger prefix exceeds its 4096-byte bound')
            raw = material[cursor:end]
            if source['values'][position] != {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}:
                raise ValueError('file-trigger prefix differs from its opaque declaration')
            values.append(raw.hex())
            cursor = end + 1
        encoded = material[start + offset:cursor]
        if source['bytes'] != len(encoded) or source['sha256'] != hashlib.sha256(encoded).hexdigest():
            raise ValueError('file-trigger prefix array differs from its audited tag')
        result.append({'tag': tag, 'hex_values': values})
    if seen != set(tags).intersection(FILE_TRIGGER_PREFIX_TAGS):
        raise ValueError('file-trigger prefix export is incomplete')
    return sorted(result, key=lambda row: row['tag'])


def file_trigger_literal(raw):
    # A conservative ASCII path-prefix profile. Preserve the final slash and
    # every admitted byte; RPM uses a string prefix, not component ancestry.
    if not 1 <= len(raw) <= 4096:
        raise ValueError('file-trigger prefix is empty or excessive')
    path = raw.decode('ascii')
    if path != '/':
        parts = path[1:].removesuffix('/').split('/')
        if (not re.fullmatch(r'/[A-Za-z0-9_+.,:@=/\-]+', path)
                or any(part in ('', '.', '..') for part in parts)):
            raise ValueError('file-trigger prefix is outside the literal path profile')
    return path


def file_trigger_prefix_observe(proof):
    # The emitted entry point calls this ONLY after fresh trigger_observe.
    audit = proof['effects']
    owners, total, raw_bytes = [], 0, 0
    installed = {}
    for kind, values in (('installed', audit['installed_script_owners']), ('incoming', audit['incoming'])):
        for owner in values:
            tags = trigger_tags(owner)
            projected = owner['file_trigger_prefix_bytes']
            expected = sorted(set(tags).intersection(FILE_TRIGGER_PREFIX_TAGS))
            if (not isinstance(projected, list) or len(projected) != len(expected)
                    or any(not isinstance(row, dict) or set(row) != {'tag', 'hex_values'} for row in projected)
                    or [row['tag'] for row in projected] != expected
                    or any(type(row['tag']) is not int for row in projected)):
                raise ValueError('file-trigger prefix projection is missing, repeated or unordered')
            groups = {entry['family']: entry for entry in trigger_groups(owner)}
            families = []
            for row in projected:
                tag, values = row['tag'], row['hex_values']
                source = tags[tag]
                if not isinstance(values, list) or len(values) != source['count']:
                    raise ValueError('file-trigger prefix projection count differs from its tag')
                family = 'filetrigger' if tag == 5069 else 'transfiletrigger'
                _, _, _, _, _, _, senses, indexes, _ = next(entry for entry in TRIGGER_ARRAYS if entry[0] == family)
                records, encoded = [], bytearray()
                for position, value in enumerate(values):
                    if (not isinstance(value, str) or not 2 <= len(value) <= 8192 or len(value) % 2
                            or not re.fullmatch(r'[0-9a-f]+', value)):
                        raise ValueError('file-trigger prefix byte encoding is unsupported')
                    raw = bytes.fromhex(value)
                    digest = hashlib.sha256(raw).hexdigest()
                    if source['values'][position] != {'bytes': len(raw), 'sha256': digest}:
                        raise ValueError('file-trigger prefix bytes differ from the current tag')
                    path = file_trigger_literal(raw)
                    total += 1; raw_bytes += len(raw)
                    if total > 65536 or raw_bytes > FILE_TRIGGER_PREFIX_LIMIT:
                        raise ValueError('file-trigger prefixes exceed their aggregate observation bound')
                    encoded.extend(raw + b'\0')
                    records.append({'condition_position': position, 'script_index': tags[indexes]['values'][position],
                        'declared_sense': tags[senses]['values'][position], 'prefix': path, 'bytes': len(raw), 'sha256': digest})
                if len(encoded) != source['bytes'] or hashlib.sha256(encoded).hexdigest() != source['sha256']:
                    raise ValueError('file-trigger prefix encoded array differs from the current tag')
                families.append({'family': family, 'name_tag': tag, 'source_tag_sha256': source['sha256'],
                    'slots': groups[family]['slots'], 'conditions': records})
            identity = {field: owner[field] for field in (('instance',) if kind == 'installed' else ('file', 'sha256', 'bytes'))}
            owners.append({'kind': kind, **identity, **{field: owner[field] for field in ('name', 'nevra', 'header_sha256')},
                'families': families})
            if kind == 'installed': installed[owner['instance']] = projected
    for owner in audit['removals']:
        if owner['file_trigger_prefix_bytes'] != installed.get(owner['instance'], []):
            raise ValueError('file-trigger removal prefix bytes differ from the installed owner')
    material = json.dumps(owners, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['file_trigger_prefix_observation'] = {'schema': 1, 'owners': owners, 'prefixes': total,
        'prefix_bytes': raw_bytes, 'owners_bytes': len(material), 'owners_sha256': hashlib.sha256(material).hexdigest(),
        'literal_prefixes_observed': bool(total), 'baseline_sha256': proof['baseline']['sha256'],
        'inventory_sha256': audit['installed_versions']['entries_sha256'],
        'scope': 'literal declared file/transfile prefix bytes and source positions ONLY; no file matching or selection',
        **{flag: False for flag in ('all_condition_text_available', 'conditions_evaluated', 'prefix_matches_observed',
            'transaction_file_actions_observed', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'installed_headers_authenticated', 'script_policy_satisfied',
            'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

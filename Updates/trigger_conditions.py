"""Observe bounded declared trigger name/EVR strings, never evaluate a match."""

import hashlib
import json
import re


TRIGGER_CONDITION_TAGS = (1066, 1067, 5071, 5081)
TRIGGER_CONDITION_LIMIT = 8 * 1024 * 1024
TRIGGER_COMPARISONS = {0: None, 2: '<', 4: '>', 8: '=', 10: '<=', 12: '>='}


def trigger_condition_export(material, audited):
    # Reuse the exact admitted export/string/hash collector. File names stay
    # in the separate accepted prefix projection; bodies are never requested.
    return file_trigger_export(material, audited, TRIGGER_CONDITION_TAGS)


def trigger_condition_values(owner, tags):
    projected = owner['trigger_condition_bytes']
    expected = sorted(set(tags).intersection(TRIGGER_CONDITION_TAGS))
    if (not isinstance(projected, list) or len(projected) != len(expected)
            or any(not isinstance(row, dict) or set(row) != {'tag', 'hex_values'} for row in projected)
            or [row['tag'] for row in projected] != expected
            or any(type(row['tag']) is not int for row in projected)):
        raise ValueError('trigger condition projection is missing, repeated or unordered')
    result = {}
    for row in projected:
        tag, values, encoded = row['tag'], row['hex_values'], bytearray()
        source = tags[tag]
        if not isinstance(values, list) or len(values) != source['count']:
            raise ValueError('trigger condition projection count differs from its tag')
        bound = 256 if tag == 1066 else 1024
        raw_values = []
        for position, value in enumerate(values):
            if (not isinstance(value, str) or len(value) > 2 * bound or len(value) % 2
                    or not re.fullmatch(r'(?:[0-9a-f]{2})*', value)):
                raise ValueError('trigger condition byte encoding is unsupported')
            raw = bytes.fromhex(value)
            if source['values'][position] != {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}:
                raise ValueError('trigger condition bytes differ from the current tag')
            raw_values.append(raw); encoded.extend(raw + b'\0')
        if len(encoded) != source['bytes'] or hashlib.sha256(encoded).hexdigest() != source['sha256']:
            raise ValueError('trigger condition array differs from the current tag')
        result[tag] = raw_values
    return result


def trigger_condition_literal(family, name, raw_evr, sense):
    if type(sense) is not int or not 0 <= sense <= 2**32 - 1:
        raise ValueError('trigger condition sense is unsupported')
    mask = sense & 14
    if mask not in TRIGGER_COMPARISONS:
        raise ValueError('trigger condition comparison mask is outside the declared profile')
    evr = raw_evr.decode('ascii')
    if len(raw_evr) > 1024:
        raise ValueError('trigger condition EVR exceeds its bound')
    parts = None
    if family == 'trigger':
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', name)):
            raise ValueError('trigger condition name is outside the package-name profile')
        if bool(mask) != bool(evr):
            raise ValueError('trigger condition comparison and EVR declaration disagree')
        if evr:
            match = re.fullmatch(r'(?:(0|[1-9][0-9]{0,9}):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?', evr)
            if not match or int(match[1] or '0') > 2**32 - 1:
                raise ValueError('trigger condition EVR is outside the canonical declaration profile')
            # Preserve omission, not package-EVR defaults or overlap semantics.
            parts = {'epoch': match[1], 'version': match[2], 'release': match[3]}
    elif family in ('filetrigger', 'transfiletrigger'):
        if mask or evr:
            raise ValueError('versioned file-trigger condition is outside the declared profile')
    else:
        raise ValueError('trigger condition family is unsupported')
    return {'name': name, 'evr': evr, 'evr_parts': parts, 'comparison_mask': mask,
        'declared_operator': TRIGGER_COMPARISONS[mask], 'declared_sense': sense,
        'uninterpreted_sense_bits': sense & ~(14 | sum(TRIGGER_PHASES))}


def trigger_condition_observe(proof):
    # Shipped entry point first runs fresh trigger_observe; then the accepted
    # prefix guard is re-executed here, never borrowed from an old receipt.
    proof = file_trigger_prefix_observe(proof)
    audit, owners, installed, count, total = proof['effects'], [], {}, 0, 0
    for kind, values in (('installed', audit['installed_script_owners']), ('incoming', audit['incoming'])):
        for owner in values:
            tags = trigger_tags(owner)
            raw = trigger_condition_values(owner, tags)
            prefixes = {row['tag']: row['hex_values'] for row in owner['file_trigger_prefix_bytes']}
            families = []
            for group in trigger_groups(owner):
                family = group['family']
                _, _, _, _, names, versions, senses, indexes, _ = next(row for row in TRIGGER_ARRAYS if row[0] == family)
                records = []
                for position, raw_evr in enumerate(raw[versions]):
                    raw_name = raw[names][position] if family == 'trigger' else bytes.fromhex(prefixes[names][position])
                    literal = trigger_condition_literal(family, raw_name.decode('ascii'), raw_evr, tags[senses]['values'][position])
                    count += 1; total += len(raw_name) + len(raw_evr)
                    if count > 65536 or total > TRIGGER_CONDITION_LIMIT:
                        raise ValueError('trigger conditions exceed their aggregate observation bound')
                    records.append({'condition_position': position, 'script_index': tags[indexes]['values'][position], **literal,
                        'name_sha256': hashlib.sha256(raw_name).hexdigest(), 'evr_sha256': hashlib.sha256(raw_evr).hexdigest()})
                families.append({'family': family, 'source_tags': group['source_tags'], 'slots': group['slots'], 'conditions': records})
            fields = ('instance',) if kind == 'installed' else ('file', 'sha256', 'bytes')
            owners.append({'kind': kind, **{field: owner[field] for field in fields},
                **{field: owner[field] for field in ('name', 'nevra', 'header_sha256')}, 'families': families})
            if kind == 'installed': installed[owner['instance']] = owner['trigger_condition_bytes']
    for owner in audit['removals']:
        if owner['trigger_condition_bytes'] != installed.get(owner['instance'], []):
            raise ValueError('trigger removal conditions differ from the installed owner')
    material = json.dumps(owners, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['trigger_condition_observation'] = {'schema': 1, 'owners': owners, 'conditions': count,
        'condition_bytes': total, 'owners_bytes': len(material), 'owners_sha256': hashlib.sha256(material).hexdigest(),
        'declared_condition_strings_observed': bool(count), 'baseline_sha256': proof['baseline']['sha256'],
        'inventory_sha256': audit['installed_versions']['entries_sha256'],
        'scope': 'declared name/EVR/operator/position correspondence ONLY; no package/file match or eligibility',
        **{flag: False for flag in ('evr_comparisons_performed', 'conditions_evaluated', 'package_matches_observed',
            'prefix_matches_observed', 'transaction_file_actions_observed', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'installed_headers_authenticated', 'script_policy_satisfied', 'removal_policy_satisfied',
            'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

"""Project every observed installed header identity; no version or trust policy."""

import hashlib
import json
import re


INSTALLED_VERSION_LIMIT = 8 * 1024 * 1024
INSTALLED_VERSION_FIELDS = ('instance', 'name', 'nevra', 'header_bytes', 'header_sha256')


def installed_version_inventory(observations, baseline):
    if (not isinstance(observations, dict) or not 1 <= len(observations) <= 32768
            or not isinstance(baseline, dict) or type(baseline.get('headers')) is not int
            or baseline['headers'] != len(observations)
            or not isinstance(baseline.get('sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', baseline['sha256'])
            or any(type(key) is not int or not 1 <= key <= 2**32 - 1 for key in observations)):
        raise ValueError('installed version inventory baseline is missing or inconsistent')
    entries, encoded, size = [], [], 2
    for instance, source in sorted(observations.items()):
        if not isinstance(source, dict): raise ValueError('installed version observation is not a record')
        entry = {name: source[name] for name in INSTALLED_VERSION_FIELDS}
        if (type(entry['instance']) is not int or entry['instance'] != instance
                or not isinstance(entry['name'], str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', entry['name'])
                or not isinstance(entry['nevra'], str) or not 0 < len(entry['nevra']) <= 1024
                or not entry['nevra'].startswith(entry['name'] + '-')
                or any(ord(value) < 33 or ord(value) > 126 for value in entry['nevra'])
                or type(entry['header_bytes']) is not int or not 8 <= entry['header_bytes'] <= 8 * 1024 * 1024
                or not isinstance(entry['header_sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', entry['header_sha256'])):
            raise ValueError('installed version observation identity is unsupported')
        data = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('ascii')
        size += len(data) + bool(entries)
        if size > INSTALLED_VERSION_LIMIT: raise ValueError('installed version inventory exceeds its bound')
        entries.append(entry); encoded.append(data)
    observed = hashlib.sha256(json.dumps([(entry['instance'], entry['header_sha256']) for entry in entries],
                                        separators=(',', ':')).encode()).hexdigest()
    if observed != baseline['sha256']:
        raise ValueError('installed version inventory differs from the observed header baseline')
    material = b'[' + b','.join(encoded) + b']'
    if len(material) != size: raise ValueError('installed version serialization differs from its bound')
    return {
        'schema': 1, 'entries': entries, 'entries_bytes': size,
        'entries_sha256': hashlib.sha256(material).hexdigest(), 'baseline_sha256': observed,
        'headers': len(entries), 'complete_observed_header_inventory': True,
        'scope': 'ALL observed installed header instances and native identity declarations, including non-script owners',
        **{name: False for name in (
            'installed_headers_authenticated', 'identity_fields_independently_authenticated',
            'snapshot_atomic', 'all_incoming_versions_checked', 'kernel_version_policy_satisfied',
            'freshness_proven', 'anti_rollback_proven', 'installation_authorized', 'server_ready')},
    }

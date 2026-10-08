"""Observe native overlaps of declared Provides; never select trigger sources."""

import ctypes as C
import hashlib
import json
import os
import platform


PROVIDER_PAIR_LIMIT = 16384
PROVIDER_PROBES = tuple(
    (('probe', left, 8), ('probe', right, mask), expected)
    for left, right, mask, expected in TRIGGER_RANGE_PROBES
) + (
    (('probe', '1.0', 8), ('other', '1.0', 8), 0),
    (('probe', '', 0), ('other', '', 0), 0),
    (('probe', '', 0), ('probe', '9:2.0-1', 8), 1),
    (('probe', '1.0', 8), ('probe', '', 0), 1),
    (('probe', '1.0', 2), ('probe', '2.0', 4), 0),
    (('probe', '1.0', 4), ('probe', '2.0', 2), 1),
    (('probe', '1.0', 10), ('probe', '1.0', 12), 1),
    (('probe', '1.0', 0x80000008), ('probe', '2.0', 65536 | 4), 0),
)


def provider_literal(name, evr, flags):
    # Only relevant exact names are interpreted. The accepted declarations of
    # unrelated SONAME/rpmlib/file/rich capabilities stay opaque and committed.
    if not isinstance(name, str) or not isinstance(evr, str):
        raise ValueError('provider dependency strings are unsupported')
    if type(flags) is not int or not 0 <= flags <= 2**32 - 1 or flags & 1:
        raise ValueError('provider dependency flags or legacy serial bit are unsupported')
    return trigger_condition_literal('trigger', name, evr.encode('ascii'), flags)


def provider_native():
    if (platform.machine() not in ('x86_64', 'aarch64') or C.sizeof(C.c_void_p) != 8
            or C.sizeof(C.c_ulong) != 8 or C.sizeof(C.c_int) != 4 or C.sizeof(C.c_uint) != 4):
        raise ValueError('provider dependency comparison ABI is unsupported')
    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, 'RPMVERSION').value != b'4.18.2':
        raise ValueError('provider dependency comparison RPM version is not vetted')
    signatures = {'rpmdsSingle': (C.c_void_p, C.c_int, C.c_char_p, C.c_char_p, C.c_uint),
        'rpmdsCount': (C.c_int, C.c_void_p), 'rpmdsIx': (C.c_int, C.c_void_p),
        'rpmdsTagN': (C.c_int, C.c_void_p), 'rpmdsN': (C.c_char_p, C.c_void_p),
        'rpmdsEVR': (C.c_char_p, C.c_void_p), 'rpmdsFlags': (C.c_uint, C.c_void_p),
        'rpmdsCompare': (C.c_int, C.c_void_p, C.c_void_p),
        'rpmdsFree': (C.c_void_p, C.c_void_p)}
    api = {}
    for name, (result, *arguments) in signatures.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('provider dependency symbol is missing: ' + name) from error
        function.restype, function.argtypes = result, tuple(arguments); api[name] = function
    def compare(left, right):
        handles, expected = [], []
        try:
            for tag, value in zip((1047, 1066), (left, right)):
                name, evr, flags = value
                provider_literal(name, evr, flags)
                name, evr = name.encode('ascii'), evr.encode('ascii')
                handle = api['rpmdsSingle'](tag, name, evr, flags)
                if not handle: raise ValueError('provider dependency allocation failed')
                if handle in handles: raise ValueError('provider dependency handles unexpectedly alias')
                handles.append(handle); expected.append((1, 0, tag, name, evr, flags))
                actual = tuple(api[symbol](handle) for symbol in
                    ('rpmdsCount', 'rpmdsIx', 'rpmdsTagN', 'rpmdsN', 'rpmdsEVR', 'rpmdsFlags'))
                if actual != expected[-1]:
                    raise ValueError('provider dependency receipt differs from the declaration')
            result = api['rpmdsCompare'](*handles)
            if type(result) is not int or result not in (0, 1):
                raise ValueError('provider dependency overlap result is unsupported')
            for handle, receipt in zip(handles, expected):
                actual = tuple(api[symbol](handle) for symbol in
                    ('rpmdsCount', 'rpmdsIx', 'rpmdsTagN', 'rpmdsN', 'rpmdsEVR', 'rpmdsFlags'))
                if actual != receipt:
                    raise ValueError('provider dependency receipt changed during comparison')
            return result
        finally:
            failures = []
            for handle in handles:
                try:
                    if api['rpmdsFree'](handle) is not None:
                        failures.append(ValueError('provider dependency handle cleanup failed'))
                except BaseException as error: failures.append(error)
            if failures: raise failures[0]
    return compare


def provider_observe(proof, comparator_factory=provider_native):
    # Rebuild all accepted current guards and raw declarations on THIS capture.
    proof = provides_observe(proof)
    declarations = proof['provides_observation']
    conditions = [(owner, condition) for owner in proof['trigger_condition_observation']['owners']
                  for family in owner['families'] if family['family'] == 'trigger'
                  for condition in family['conditions']]
    names = {condition['name'].encode('ascii').hex() for _, condition in conditions}
    sources = {}
    for owner in declarations['owners']:
        for row in owner['provides']:
            if row['name_hex'] in names:
                name, evr = bytes.fromhex(row['name_hex']).decode('ascii'), bytes.fromhex(row['evr_hex']).decode('ascii')
                literal = provider_literal(name, evr, row['declared_flags'])
                source = {'owner': {key: value for key, value in owner.items() if key not in ('source_tags', 'provides')},
                    **row, 'evr': evr, 'evr_parts': literal['evr_parts'],
                    'comparison_mask': literal['comparison_mask'], 'uninterpreted_sense_bits': row['declared_flags'] & ~15}
                sources.setdefault(name, []).append(source)
    pairs = sum(len(sources.get(condition['name'], ())) for _, condition in conditions)
    if pairs > PROVIDER_PAIR_LIMIT:
        raise ValueError('provider dependency comparison pairs exceed their bound')
    for _, condition in conditions:
        if sources.get(condition['name']):
            provider_literal(condition['name'], condition['evr'], condition['declared_sense'])
    compare, calls, controls = comparator_factory() if pairs else None, 0, []
    def checked(left, right):
        nonlocal calls
        calls += 1
        if calls > 4 * len(PROVIDER_PROBES) + 2 * PROVIDER_PAIR_LIMIT:
            raise ValueError('provider dependency native work exceeds its bound')
        result = compare(left, right)
        if type(result) is not int or result not in (0, 1):
            raise ValueError('provider dependency comparison result is unsupported')
        return result
    if pairs:
        for left, right, expected in PROVIDER_PROBES:
            observed = [checked(left, right), checked(right, left), checked(left, left), checked(right, right)]
            if observed != [expected, expected, 1, 1]:
                raise ValueError('provider dependency native participation control failed')
            controls.append({'left': left, 'right': right, 'observed': observed})
    records = []
    for owner, condition in conditions:
        compared, right = [], (condition['name'], condition['evr'], condition['declared_sense'])
        for source in sources.get(condition['name'], ()):
            left = (condition['name'], source['evr'], source['declared_flags'])
            forward, reverse = checked(left, right), checked(right, left)
            if forward != reverse: raise ValueError('provider dependency overlap is not symmetric')
            compared.append({'source': source, 'declared_dependency_overlap': bool(forward)})
        records.append({'owner': {key: value for key, value in owner.items() if key != 'families'},
            'condition_position': condition['condition_position'], 'script_index': condition['script_index'],
            'name': condition['name'], 'evr': condition['evr'], 'declared_sense': condition['declared_sense'],
            'sources_compared': compared})
    material = json.dumps(records, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['provider_match_observation'] = {'schema': 1, 'conditions': records, 'ordinary_conditions': len(conditions),
        'pairs_compared': pairs, 'native_comparator_invocations': calls, 'participation_controls': controls,
        'native_participation_checked': bool(pairs), 'declared_dependency_ranges_compared': bool(pairs),
        'conditions_bytes': len(material), 'conditions_sha256': hashlib.sha256(material).hexdigest(),
        'provides_sha256': declarations['owners_sha256'],
        'declaration_sha256': proof['trigger_condition_observation']['owners_sha256'],
        'baseline_sha256': proof['baseline']['sha256'], 'inventory_sha256': declarations['inventory_sha256'],
        'scope': 'exact-name declared Provides vs ordinary trigger dependencies ONLY; ALL observed sources remain UNSELECTED',
        **{flag: False for flag in ('actual_header_dependency_matches_observed', 'package_source_name_gate_satisfied',
            'provider_architectures_selected', 'transaction_temporal_sources_selected', 'trigger_phase_selected',
            'trigger_selection_complete', 'execution_order_complete', 'script_execution_plan_complete',
            'installed_headers_authenticated', 'native_library_identity_authenticated', 'script_policy_satisfied',
            'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

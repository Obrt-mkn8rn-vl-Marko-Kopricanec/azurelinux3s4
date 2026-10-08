"""Native overlaps of observed package-EVR declarations, never trigger eligibility."""

import ctypes as C
import os
import platform


TRIGGER_RANGE_LIMIT = 16384
TRIGGER_RANGE_PROBES = (
    ('1.0-1', '2.0', 2, 1), ('1.0-1', '2.0', 4, 0),
    ('1.0-1', '2.0', 8, 0), ('2.0-1', '1.0', 4, 1),
    ('2.0-1', '1.0', 2, 0), ('1.0-1', '1.0', 8, 1),
    ('1.0-1', '1.0', 2, 0), ('1.0-1', '1.0', 10, 1),
    ('1.0-1', '1.0', 12, 1), ('1.0-2', '1.0-1', 8, 0),
    ('1.0-2', '1.0-1', 4, 1), ('0:1.0-1', '1.0', 8, 1),
    ('2:1.0-1', '1:2.0', 4, 1), ('1.0~rc1-1', '1.0', 2, 1),
    ('1.0^git-1', '1.0', 4, 1), ('1.0^git-1', '1.0.1', 2, 1),
    ('1.01-1', '1.1-1', 8, 1),
)


def trigger_range_native():
    if (platform.machine() not in ('x86_64', 'aarch64') or C.sizeof(C.c_void_p) != 8
            or C.sizeof(C.c_ulong) != 8 or C.sizeof(C.c_int) != 4 or C.sizeof(C.c_uint) != 4):
        raise ValueError('trigger range comparison ABI is unsupported')
    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, 'RPMVERSION').value != b'4.18.2':
        raise ValueError('trigger range comparison RPM version is not vetted')
    signatures = {'rpmverParse': (C.c_void_p, C.c_char_p),
        'rpmverE': (C.c_char_p, C.c_void_p), 'rpmverV': (C.c_char_p, C.c_void_p),
        'rpmverR': (C.c_char_p, C.c_void_p), 'rpmverFree': (C.c_void_p, C.c_void_p),
        'rpmverOverlap': (C.c_int, C.c_void_p, C.c_uint, C.c_void_p, C.c_uint)}
    api = {}
    for name, (result, *arguments) in signatures.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('trigger range comparison symbol is missing: ' + name) from error
        function.restype, function.argtypes = result, tuple(arguments); api[name] = function
    def compare(left, left_flags, right, right_flags):
        if (type(left_flags) is not int or type(right_flags) is not int
                or left_flags not in (2, 4, 8, 10, 12) or right_flags not in (2, 4, 8, 10, 12)):
            raise ValueError('trigger range native flags are unsupported')
        handles = []
        try:
            for value in (left, right):
                parts = trigger_condition_literal('trigger', 'probe', value.encode('ascii'), 65536 | 8)['evr_parts']
                if parts is None: raise ValueError('trigger range native EVR is empty')
                handle = api['rpmverParse'](value.encode('ascii'))
                if not handle: raise ValueError('trigger range native EVR parse failed')
                if handle in handles: raise ValueError('trigger range native handles unexpectedly alias')
                handles.append(handle)
                for symbol, field in (('rpmverE', 'epoch'), ('rpmverV', 'version'), ('rpmverR', 'release')):
                    expected = parts[field].encode('ascii') if parts[field] is not None else None
                    if api[symbol](handle) != expected:
                        raise ValueError('trigger range native parsed fields differ from the declaration')
            result = api['rpmverOverlap'](handles[0], left_flags, handles[1], right_flags)
            if type(result) is not int or result not in (0, 1):
                raise ValueError('trigger range native overlap result is unsupported')
            return result
        finally:
            failures = []
            for handle in handles:
                try:
                    if api['rpmverFree'](handle) is not None:
                        failures.append(ValueError('trigger range native handle cleanup failed'))
                except BaseException as error: failures.append(error)
            if failures: raise failures[0]
    return compare


def trigger_range_source(kind, entry):
    name, nevra = entry['name'], entry['nevra']
    architecture = nevra.rsplit('.', 1)[-1]
    if architecture not in ('x86_64', 'aarch64', 'noarch') or not nevra.startswith(name + '-'):
        raise ValueError('trigger range relevant source architecture/identity is unsupported')
    evr = nevra[len(name) + 1:-(len(architecture) + 1)]
    parsed = trigger_condition_literal('trigger', name, evr.encode('ascii'), 65536 | 8)
    if parsed['evr_parts'] is None or parsed['evr_parts']['release'] is None:
        raise ValueError('trigger range relevant source has no package release')
    fields = ('instance',) if kind == 'installed' else ('file', 'sha256', 'bytes')
    return {'kind': kind, **{field: entry[field] for field in fields},
        **{field: entry[field] for field in ('name', 'nevra', 'header_sha256')},
        'architecture': architecture, 'evr': evr}


def trigger_range_observe(proof, comparator_factory=trigger_range_native):
    # Always reconstruct the qualified declarations on THIS private capture.
    proof = trigger_condition_observe(proof)
    declaration = proof['trigger_condition_observation']
    conditions = [(owner, condition) for owner in declaration['owners'] for family in owner['families']
                  if family['family'] == 'trigger' for condition in family['conditions']]
    names = {condition['name'] for _, condition in conditions if condition['comparison_mask']}
    sources = {}
    for kind, entries in (('installed', proof['effects']['installed_versions']['entries']), ('incoming', proof['effects']['incoming'])):
        for entry in entries:
            if entry['name'] in names:
                sources.setdefault(entry['name'], []).append(trigger_range_source(kind, entry))
    pairs = sum(len(sources.get(condition['name'], ())) for _, condition in conditions if condition['comparison_mask'])
    if pairs > TRIGGER_RANGE_LIMIT:
        raise ValueError('trigger range comparison pairs exceed their bound')
    controls, calls, compare = [], 0, comparator_factory() if pairs else None
    def checked(left, left_flags, right, right_flags):
        nonlocal calls
        calls += 1
        if calls > 4 * len(TRIGGER_RANGE_PROBES) + 2 * TRIGGER_RANGE_LIMIT:
            raise ValueError('trigger range native work exceeds its bound')
        result = compare(left, left_flags, right, right_flags)
        if type(result) is not int or result not in (0, 1):
            raise ValueError('trigger range comparison result is unsupported')
        return result
    if pairs:
        for left, right, mask, expected in TRIGGER_RANGE_PROBES:
            observed = [checked(left, 8, right, mask), checked(right, mask, left, 8),
                        checked(left, 8, left, 8), checked(right, mask, right, mask)]
            if observed != [expected, expected, 1, 1]:
                raise ValueError('trigger range native participation control failed')
            controls.append({'source_evr': left, 'condition_evr': right, 'comparison_mask': mask, 'observed': observed})
    records = []
    for owner, condition in conditions:
        compared = []
        if condition['comparison_mask']:
            for source in sources.get(condition['name'], ()):
                forward = checked(source['evr'], 8, condition['evr'], condition['comparison_mask'])
                reverse = checked(condition['evr'], condition['comparison_mask'], source['evr'], 8)
                if forward != reverse: raise ValueError('trigger range native overlap is not symmetric')
                compared.append({'source': source, 'range_overlap': bool(forward)})
        records.append({'owner': {key: value for key, value in owner.items() if key != 'families'},
            'condition_position': condition['condition_position'], 'script_index': condition['script_index'],
            'name': condition['name'], 'condition_evr': condition['evr'], 'comparison_mask': condition['comparison_mask'],
            'uninterpreted_sense_bits': condition['uninterpreted_sense_bits'],
            'versioned_range': bool(condition['comparison_mask']), 'sources_compared': compared})
    proof['trigger_range_observation'] = {'schema': 1, 'conditions': records, 'ordinary_conditions': len(conditions),
        'pairs_compared': pairs, 'native_comparator_invocations': calls, 'participation_controls': controls,
        'native_participation_checked': bool(pairs), 'observed_evr_ranges_compared': bool(pairs),
        'declaration_sha256': declaration['owners_sha256'], 'baseline_sha256': proof['baseline']['sha256'],
        'inventory_sha256': proof['effects']['installed_versions']['entries_sha256'],
        'scope': 'same-name observed package EVR vs declared normal-trigger ranges ONLY; not actual provided dependencies/phase/state/eligibility',
        **{flag: False for flag in ('unversioned_conditions_evaluated', 'actual_provides_observed', 'package_trigger_matches_observed',
            'transaction_temporal_sources_selected', 'prefix_matches_observed', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'installed_headers_authenticated', 'native_library_identity_authenticated',
            'script_policy_satisfied', 'removal_policy_satisfied', 'rollback_policy_satisfied',
            'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

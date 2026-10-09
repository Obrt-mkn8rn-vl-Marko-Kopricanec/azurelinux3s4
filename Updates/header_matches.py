"""Query captured Header Provides, without selecting any transaction source."""
import ctypes as C
import hashlib
import json
import os
import struct

HEADER_MATCH_PAIR_LIMIT = 16384
HEADER_MATCH_BYTES = 64 * 1024 * 1024
HEADER_MATCH_ROWS = 1048576


def header_match_probe(value):
    name, evr, flags = value
    provider_literal(name, evr, flags)
    names, versions = name.encode('ascii') + b'\0', evr.encode('ascii') + b'\0'
    data = names + b'\0' * (-len(names) % 4)
    flag_offset = len(data); data += struct.pack('>I', flags)
    version_offset = len(data); data += versions
    # A bare v3 header is upgraded on import/export by the pinned library.
    # Supply the complete HEADERIMMUTABLE region and its matching trailer.
    region_offset = len(data)
    entries = ((63, 7, region_offset, 16), (1047, 8, 0, 1), (1112, 4, flag_offset, 1), (1113, 8, version_offset, 1))
    data += struct.pack('>IIiI', 63, 7, -16 * len(entries), 16)
    material = struct.pack('>II', len(entries), len(data)) + b''.join(struct.pack('>IIII', *entry) for entry in entries) + data
    audited = audit_header(material)
    rows = provides_records(provides_export(material, audited))
    arrays = [(1047, [{'name_hex': row['name_hex'], 'evr_hex': row['evr_hex'], 'flags': row['declared_flags']} for row in rows]), (1066, [])]
    return material, arrays


def header_match_native():
    # Reuse admitted ABI/import/export/readback/ownership and post-callback
    # correspondence; the Header is borrowed only while that owner holds it.
    reimport = header_input_native()
    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, 'RPMVERSION').value != b'4.18.2':
        raise ValueError('Header match RPM version is not vetted')
    signatures = {'rpmdsSingle': (C.c_void_p, C.c_int, C.c_char_p, C.c_char_p, C.c_uint),
        'rpmdsCount': (C.c_int, C.c_void_p), 'rpmdsIx': (C.c_int, C.c_void_p),
        'rpmdsTagN': (C.c_int, C.c_void_p), 'rpmdsN': (C.c_char_p, C.c_void_p),
        'rpmdsEVR': (C.c_char_p, C.c_void_p), 'rpmdsFlags': (C.c_uint, C.c_void_p),
        'rpmdsAnyMatchesDep': (C.c_int, C.c_void_p, C.c_void_p, C.c_int),
        'rpmdsFree': (C.c_void_p, C.c_void_p)}
    api = {}
    for name, (result, *arguments) in signatures.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('Header match symbol is missing: ' + name) from error
        function.restype, function.argtypes = result, tuple(arguments); api[name] = function
    def query(material, arrays, declaration):
        name, evr, flags = declaration; provider_literal(name, evr, flags)
        name, evr = name.encode('ascii'), evr.encode('ascii')
        expected = (1, 0, 1066, name, evr, flags)
        def after(header, dependencies, caller_address):
            request = None
            name_buffer, evr_buffer = C.create_string_buffer(name), C.create_string_buffer(evr)
            argument_addresses = (C.addressof(name_buffer), C.addressof(evr_buffer))
            def readback():
                if name_buffer.raw != name + b'\0' or evr_buffer.raw != evr + b'\0':
                    raise ValueError('Header match caller argument changed')
                if tuple(api[symbol](request) for symbol in
                         ('rpmdsCount', 'rpmdsIx', 'rpmdsTagN', 'rpmdsN', 'rpmdsEVR', 'rpmdsFlags')) != expected:
                    raise ValueError('Header match request receipt differs')
            try:
                pointer = api['rpmdsSingle'](1066, name_buffer, evr_buffer, flags)
                if not pointer: raise ValueError('Header match request allocation failed')
                if pointer in (header, caller_address, *dependencies, *argument_addresses):
                    raise ValueError('Header match request aliases a borrowed allocation')
                request = pointer; readback()
                # Pinned API documents nopromote as UNUSED, not epoch policy.
                forward = api['rpmdsAnyMatchesDep'](header, request, 1); readback()
                repeated = api['rpmdsAnyMatchesDep'](header, request, 1); readback()
                if type(forward) is not int or type(repeated) is not int or forward not in (0, 1) or repeated != forward:
                    raise ValueError('Header match result is unsupported or changes')
                return forward
            finally:
                if request and api['rpmdsFree'](request) is not None:
                    raise ValueError('Header match request cleanup failed')
        return reimport(material, arrays, after)
    return query


def header_match_observe(proof, native_factory=header_match_native, comparator_factory=None):
    proof = header_input_observe(proof, comparator_factory=comparator_factory)
    admitted = proof['header_input_observation']
    by_key = {trigger_source_key(value['owner']): value for value in admitted['owners']}
    raw = {('installed', value['instance']): value for value in proof['effects'].get('installed_header_exports', [])}
    raw.update({('incoming', value['file']): value for value in proof['effects']['incoming']})
    records, work_bytes, work_rows = [], 0, 0
    for condition in proof['trigger_source_observation']['conditions']:
        for source in condition['package_name_sources']:
            key = trigger_source_key(source['owner']); imported = by_key[key]
            if imported['owner'] != source['owner']:
                raise ValueError('Header match source differs from its admitted export')
            material = header_input_material(raw[key]); work_bytes += len(material)
            if len(records) >= HEADER_MATCH_PAIR_LIMIT or work_bytes > HEADER_MATCH_BYTES:
                raise ValueError('Header match pairs/bytes exceed their bound')
            arrays = [(value['tag'], value['rows']) for value in imported['dependency_arrays']]
            work_rows += sum(len(rows) for _, rows in arrays)
            if work_rows > HEADER_MATCH_ROWS:
                raise ValueError('Header match repeated rows exceed their bound')
            records.append((condition, source, material, arrays))
    query = native_factory() if records else None
    calls = 0
    def checked(material, arrays, declaration):
        nonlocal calls
        calls += 1
        if calls > 4 * len(PROVIDER_PROBES) + HEADER_MATCH_PAIR_LIMIT:
            raise ValueError('Header match native work exceeds its bound')
        result = query(material, arrays, declaration)
        if type(result) is not int or result not in (0, 1):
            raise ValueError('Header match query result is unsupported')
        return result
    controls = []
    if records:
        for left, right, expected in PROVIDER_PROBES:
            observed = [checked(*header_match_probe(a), b) for a, b in ((left, right), (right, left), (left, left), (right, right))]
            if observed != [expected, expected, 1, 1]:
                raise ValueError('Header match native participation control failed')
            controls.append({'left': left, 'right': right, 'observed': observed})
    observations = []
    for condition, source, material, arrays in records:
        result = checked(material, arrays, (condition['name'], condition['evr'], condition['declared_sense']))
        if bool(result) != source['same_name_declared_provides_overlap']:
            raise ValueError('Header match differs from complete declared Provides')
        observations.append({'condition_owner': condition['owner'], 'condition_position': condition['condition_position'],
            'script_index': condition['script_index'], 'name': condition['name'], 'evr': condition['evr'],
            'declared_sense': condition['declared_sense'], 'source_owner': source['owner'],
            'captured_header_dependency_match': bool(result), 'declared_provides_agree': True})
    encoded = json.dumps(observations, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['header_match_observation'] = {'schema': 1, 'pairs': observations, 'pairs_queried': len(records),
        'captured_header_bytes_queried': work_bytes, 'native_header_queries_observed': bool(records),
        'captured_dependency_rows_queried': work_rows,
        'native_participation_checked': bool(records), 'participation_controls': controls,
        'native_query_calls': 2 * calls, 'pairs_bytes': len(encoded), 'pairs_sha256': hashlib.sha256(encoded).hexdigest(),
        'header_input_owners_sha256': admitted['owners_sha256'], 'source_conditions_sha256': proof['trigger_source_observation']['conditions_sha256'],
        'baseline_sha256': admitted['baseline_sha256'], 'inventory_sha256': admitted['inventory_sha256'],
        'scope': 'SAME captured/imported Header query correspondence ONLY; sources/events remain UNSELECTED',
        **{flag: False for flag in ('headers_authenticated', 'native_library_identity_authenticated',
            'transaction_temporal_sources_selected', 'trigger_phase_selected', 'provider_architectures_selected',
            'trigger_eligibility_complete', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied',
            'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

"""Complete audited export/import and dependency readback, not Header matching."""
import ctypes as C
import hashlib
import json
import os
import platform

header_exports_projection = False
HEADER_INPUT_BYTES = 8 * 1024 * 1024
HEADER_INPUT_ROWS = 131072


def header_input_material(value):
    encoded = value['header_export_hex']
    if (not isinstance(encoded, str) or len(encoded) != 2 * value['header_bytes']
            or not 8 <= value['header_bytes'] <= HEADER_INPUT_BYTES
            or any(char not in '0123456789abcdef' for char in encoded)):
        raise ValueError('Header input export encoding/size is unsupported')
    material = bytes.fromhex(encoded)
    if hashlib.sha256(material).hexdigest() != value['header_sha256']:
        raise ValueError('Header input export digest differs from its owner')
    return material


def header_input_native():
    if (platform.machine() not in ('x86_64', 'aarch64') or C.sizeof(C.c_void_p) != 8
            or C.sizeof(C.c_ulong) != 8 or C.sizeof(C.c_int) != 4 or C.sizeof(C.c_uint) != 4):
        raise ValueError('Header input ABI is unsupported')
    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, 'RPMVERSION').value != b'4.18.2':
        raise ValueError('Header input RPM version is not vetted')
    signatures = {'headerImport': (C.c_void_p, C.c_void_p, C.c_uint, C.c_uint),
        'headerExport': (C.c_void_p, C.c_void_p, C.POINTER(C.c_uint)),
        'headerFree': (C.c_void_p, C.c_void_p), 'headerIsEntry': (C.c_int, C.c_void_p, C.c_int),
        'rpmdsNew': (C.c_void_p, C.c_void_p, C.c_int, C.c_int),
        'rpmdsSetIx': (C.c_int, C.c_void_p, C.c_int), 'rpmdsCount': (C.c_int, C.c_void_p),
        'rpmdsIx': (C.c_int, C.c_void_p), 'rpmdsTagN': (C.c_int, C.c_void_p),
        'rpmdsN': (C.c_char_p, C.c_void_p), 'rpmdsEVR': (C.c_char_p, C.c_void_p),
        'rpmdsFlags': (C.c_uint, C.c_void_p), 'rpmdsTi': (C.c_int, C.c_void_p),
        'rpmdsFree': (C.c_void_p, C.c_void_p)}
    api = {}
    for name, (result, *arguments) in signatures.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('Header input symbol is missing: ' + name) from error
        function.restype, function.argtypes = result, tuple(arguments); api[name] = function
    libc = C.CDLL(None); libc.free.restype = None; libc.free.argtypes = (C.c_void_p,)
    def observe(material, arrays):
        header, dependencies = None, []
        buffer = C.create_string_buffer(material, len(material))
        def exported():
            size = C.c_uint(); pointer = api['headerExport'](header, C.byref(size))
            if pointer and pointer in [header, *dependencies]:
                raise ValueError('Header input export aliases an owned handle')
            try:
                if not pointer or size.value != len(material):
                    raise ValueError('Header input native export size differs')
                if C.string_at(pointer, size.value) != material:
                    raise ValueError('Header input native export bytes differ')
            finally:
                if pointer: libc.free(pointer)
        def readback(handle, tag, rows):
            if api['rpmdsCount'](handle) != len(rows):
                raise ValueError('Header input dependency count differs')
            for position, row in enumerate(rows):
                previous = api['rpmdsIx'](handle)
                # The pinned implementation returns the previous index.
                if api['rpmdsSetIx'](handle, position) != previous:
                    raise ValueError('Header input dependency position differs')
                actual = tuple(api[name](handle) for name in ('rpmdsIx', 'rpmdsTagN', 'rpmdsN', 'rpmdsEVR', 'rpmdsFlags'))
                expected = (position, tag, bytes.fromhex(row['name_hex']), bytes.fromhex(row['evr_hex']), row['flags'])
                if actual != expected or (tag == 1066 and api['rpmdsTi'](handle) != row['script_index']):
                    raise ValueError('Header input dependency receipt differs')
        try:
            # COPY=1 with an explicit length; FAST is deliberately absent.
            header = api['headerImport'](buffer, len(material), 1)
            if not header: raise ValueError('Header input native import failed')
            if header == C.addressof(buffer):
                header = None
                raise ValueError('Header input import aliases the caller buffer')
            exported()
            for tag, rows in arrays:
                present = api['headerIsEntry'](header, tag)
                if type(present) is not int or present != int(bool(rows)):
                    raise ValueError('Header input dependency presence differs')
                handle = api['rpmdsNew'](header, tag, 0)
                if handle:
                    if handle == header or handle in dependencies:
                        raise ValueError('Header input handles unexpectedly alias')
                    dependencies.append(handle)
                if bool(handle) != bool(rows):
                    raise ValueError('Header input dependency allocation differs')
                if handle: readback(handle, tag, rows)
            for (tag, rows), handle in zip(((tag, rows) for tag, rows in arrays if rows), dependencies):
                readback(handle, tag, rows)
            exported()
            if buffer.raw != material: raise ValueError('Header input import changed the caller buffer')
        finally:
            failures = []
            for name, handle in [('rpmdsFree', value) for value in dependencies] + [('headerFree', header)]:
                if handle:
                    try:
                        if api[name](handle) is not None: failures.append(ValueError('Header input native cleanup failed'))
                    except BaseException as error: failures.append(error)
            if failures: raise failures[0]
    return observe


def header_input_observe(proof, native_factory=header_input_native, comparator_factory=None):
    proof = trigger_source_observe(proof, comparator_factory or provider_native)
    ordinary = proof['trigger_source_observation']['conditions']
    declarations = proof['provides_observation']['owners']
    records, total, row_count = [], 0, 0
    if ordinary:
        captured = proof['effects']['installed_header_exports']
        inventory = proof['effects']['installed_versions']['entries']
        if not isinstance(captured, list) or len(captured) != len(inventory):
            raise ValueError('Header input installed export inventory differs')
        raw = {}
        metadata = {('installed', value['instance']): value for value in proof['effects']['installed_script_owners']}
        for expected, value in zip(inventory, captured):
            if not isinstance(value, dict) or set(value) != {*INSTALLED_VERSION_FIELDS, 'header_export_hex'}:
                raise ValueError('Header input installed export fields differ')
            if {key: value[key] for key in INSTALLED_VERSION_FIELDS} != expected:
                raise ValueError('Header input installed export identity/order differs')
            raw[('installed', value['instance'])] = value
        for value in proof['effects']['incoming']:
            raw[('incoming', value['file'])] = value
            metadata[('incoming', value['file'])] = value
        for owner in declarations:
            value = raw[trigger_source_key(owner)]
            material = header_input_material(value); total += len(material)
            if total > HEADER_INPUT_BYTES: raise ValueError('Header input aggregate exports exceed their bound')
            audited = audit_header(material)
            if audited['header_bytes'] != owner['header_bytes'] or audited['header_sha256'] != owner['header_sha256']:
                raise ValueError('Header input audited export correspondence differs')
            provided = provides_records(provides_export(material, audited))
            if provided != owner['provides']: raise ValueError('Header input Provides projection differs')
            projected = trigger_condition_export(material, audited)
            trigger_rows = []
            for condition_owner in proof['trigger_condition_observation']['owners']:
                if trigger_source_key(condition_owner) == trigger_source_key(owner):
                    source = metadata[trigger_source_key(owner)]
                    if projected != source['trigger_condition_bytes'] or audited['tags'] != source['tags']:
                        raise ValueError('Header input trigger projection differs')
                    trigger_rows = [row for family in condition_owner['families'] if family['family'] == 'trigger'
                                    for row in family['conditions']]
            arrays = [(1047, [{'name_hex': row['name_hex'], 'evr_hex': row['evr_hex'], 'flags': row['declared_flags']}
                              for row in provided]),
                      (1066, [{'name_hex': row['name'].encode('ascii').hex(), 'evr_hex': row['evr'].encode('ascii').hex(),
                               'flags': row['declared_sense'], 'script_index': row['script_index']} for row in trigger_rows])]
            row_count += sum(len(rows) for _, rows in arrays)
            if row_count > HEADER_INPUT_ROWS: raise ValueError('Header input dependency rows exceed their bound')
            records.append((owner, material, arrays))
        observe = native_factory()
        for _, material, arrays in records: observe(material, arrays)
    observations = [{'owner': {key: value for key, value in owner.items() if key not in ('source_tags', 'provides')},
                     'dependency_arrays': [{'tag': tag, 'rows': rows} for tag, rows in arrays]}
                    for owner, _, arrays in records]
    encoded = json.dumps(observations, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['header_input_observation'] = {'schema': 1, 'owners': observations, 'headers_imported': len(records),
        'export_bytes': total, 'dependency_rows_read_back': row_count, 'complete_exports_reimported': bool(records),
        'native_dependency_fields_read_back': bool(records), 'owners_bytes': len(encoded),
        'owners_sha256': hashlib.sha256(encoded).hexdigest(), 'baseline_sha256': proof['baseline']['sha256'],
        'inventory_sha256': proof['effects']['installed_versions']['entries_sha256'],
        'source_observation_sha256': proof['trigger_source_observation']['conditions_sha256'],
        'scope': 'SAME full audited export import/export and dependency-field correspondence ONLY; no Header matching',
        **{flag: False for flag in ('actual_header_dependency_matches_observed', 'headers_authenticated',
            'native_library_identity_authenticated', 'native_participation_controls_complete',
            'trigger_phase_selected', 'transaction_temporal_sources_selected', 'provider_architectures_selected',
            'trigger_eligibility_complete', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied',
            'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

"""Observe captured ordinary-trigger iterator correspondence, not runtime selection."""
import ctypes as C
import hashlib
import json
import os

HEADER_ITERATION_HEADERS = 4096
HEADER_ITERATION_BYTES = 8 * 1024 * 1024
HEADER_ITERATION_ROWS = 131072


def header_iteration_native():
    # The accepted owner admits ABI/version/import/export and retains every
    # Header/DS/caller allocation throughout this borrowed callback.
    reimport = header_input_native()
    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, 'RPMVERSION').value != b'4.18.2':
        raise ValueError('Header iteration RPM version is not vetted')
    signatures = {'rpmdsInit': (C.c_void_p, C.c_void_p), 'rpmdsNext': (C.c_int, C.c_void_p),
        'rpmdsCount': (C.c_int, C.c_void_p), 'rpmdsIx': (C.c_int, C.c_void_p),
        'rpmdsTagN': (C.c_int, C.c_void_p), 'rpmdsN': (C.c_char_p, C.c_void_p),
        'rpmdsEVR': (C.c_char_p, C.c_void_p), 'rpmdsFlags': (C.c_uint, C.c_void_p),
        'rpmdsTi': (C.c_int, C.c_void_p)}
    api = {}
    for name, (result, *arguments) in signatures.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('Header iteration symbol is missing: ' + name) from error
        function.restype, function.argtypes = result, tuple(arguments); api[name] = function
    initialized = api['rpmdsInit'](None)
    terminal = api['rpmdsNext'](None)
    if initialized is not None or type(terminal) is not int or terminal != -1:
        raise ValueError('Header iteration NULL participation control failed')

    def iterate(material, arrays):
        def after(header, dependencies, caller_address):
            # Init returns the SAME borrowed DS; it allocates/links no handle.
            # Never read or retire an unexpected returned address.
            bound = {tag: (handle, rows) for (tag, rows), handle in
                     zip(((tag, rows) for tag, rows in arrays if rows), dependencies)}
            handle, rows = bound[1066]
            for _ in range(2):
                if api['rpmdsInit'](handle) != handle:
                    raise ValueError('Header iteration initializer changes the borrowed handle')
                if (api['rpmdsCount'](handle), api['rpmdsTagN'](handle), api['rpmdsIx'](handle)) != (len(rows), 1066, -1):
                    raise ValueError('Header iteration initial receipt differs')
                for position, row in enumerate(rows):
                    index = api['rpmdsNext'](handle)
                    if type(index) is not int or index != position:
                        raise ValueError('Header iteration position differs from the captured order')
                    actual = tuple(api[name](handle) for name in
                        ('rpmdsCount', 'rpmdsIx', 'rpmdsTagN', 'rpmdsN', 'rpmdsEVR', 'rpmdsFlags', 'rpmdsTi'))
                    expected = (len(rows), position, 1066, bytes.fromhex(row['name_hex']),
                                bytes.fromhex(row['evr_hex']), row['flags'], row['script_index'])
                    if actual != expected:
                        raise ValueError('Header iteration row receipt differs')
                index = api['rpmdsNext'](handle)
                if (type(index) is not int or index != -1
                        or (api['rpmdsCount'](handle), api['rpmdsTagN'](handle), api['rpmdsIx'](handle)) != (len(rows), 1066, -1)):
                    raise ValueError('Header iteration terminal receipt differs')
            return {'passes': 2, 'rows_per_pass': len(rows), 'initial_index': -1, 'terminal_index': -1,
                    'native_init_calls': 2, 'native_next_calls': 2 * (len(rows) + 1)}
        # Existing pre/post DS/export/caller correspondence and checked cleanup
        # still precede return. The callback owns no new native allocation.
        return reimport(material, arrays, after)
    return iterate


def header_iteration_observe(proof, native_factory=header_iteration_native, comparator_factory=None):
    proof = trigger_first_observe(proof, comparator_factory=comparator_factory)
    admitted = proof['header_input_observation']
    raw = {('installed', value['instance']): value for value in proof['effects'].get('installed_header_exports', [])}
    raw.update({('incoming', value['file']): value for value in proof['effects']['incoming']})
    records, byte_count, row_count = [], 0, 0
    for imported in admitted['owners']:
        arrays = [(value['tag'], value['rows']) for value in imported['dependency_arrays']]
        rows = next(rows for tag, rows in arrays if tag == 1066)
        if not rows: continue
        owner = imported['owner']; material = header_input_material(raw[trigger_source_key(owner)])
        byte_count += len(material); row_count += 2 * len(rows)
        if (len(records) >= HEADER_ITERATION_HEADERS or byte_count > HEADER_ITERATION_BYTES
                or row_count > HEADER_ITERATION_ROWS):
            raise ValueError('Header iteration headers/bytes/repeated rows exceed their bound')
        records.append((owner, material, arrays, rows))
    iterate = native_factory() if records else None
    observations = []
    for owner, material, arrays, rows in records:
        receipt = iterate(material, arrays)
        expected = {'passes': 2, 'rows_per_pass': len(rows), 'initial_index': -1, 'terminal_index': -1,
                    'native_init_calls': 2, 'native_next_calls': 2 * (len(rows) + 1)}
        if receipt != expected or any(type(value) is not int for value in receipt.values()):
            raise ValueError('Header iteration complete receipt differs')
        encoded_rows = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode('ascii')
        observations.append({'owner': owner, **receipt, 'rows_bytes': len(encoded_rows),
            'rows_sha256': hashlib.sha256(encoded_rows).hexdigest(), 'condition_positions': list(range(len(rows)))})
    encoded = json.dumps(observations, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['header_iteration_observation'] = {'schema': 1, 'owners': observations, 'headers_iterated': len(records),
        'export_bytes': byte_count, 'repeated_rows': row_count, 'native_iterator_correspondence_observed': bool(records),
        'null_participation_checked': bool(records), 'null_init_calls': int(bool(records)), 'null_next_calls': int(bool(records)),
        'owners_bytes': len(encoded), 'owners_sha256': hashlib.sha256(encoded).hexdigest(),
        'header_inputs_sha256': admitted['owners_sha256'], 'pair_first_sha256': proof['trigger_first_observation']['pairs_sha256'],
        'baseline_sha256': admitted['baseline_sha256'], 'inventory_sha256': admitted['inventory_sha256'],
        'scope': 'SAME captured/imported ordinary-trigger DS Init/Next order/end correspondence ONLY; runtime sources/phases/marks remain UNSELECTED',
        **{flag: False for flag in ('headers_authenticated', 'native_library_identity_authenticated',
            'database_temporal_state_observed', 'transaction_temporal_sources_selected', 'trigger_phase_selected',
            'script_slot_state_observed', 'runtime_pair_first_selection_observed', 'provider_architectures_selected',
            'trigger_eligibility_complete', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'native_participation_controls_complete', 'script_policy_satisfied',
            'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

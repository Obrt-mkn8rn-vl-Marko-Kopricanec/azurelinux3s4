"""Bind current NAME-index counts to the captured inventory, not event state."""
import ctypes as C
import hashlib
import json
import os
import platform
import re

trigger_counts_projection = False
TRIGGER_COUNT_NAMES = 32768 + 128
TRIGGER_COUNT_BYTES = 8 * 1024 * 1024
TRIGGER_COUNT_AUTHORITIES = ('headers_authenticated', 'native_library_identity_authenticated',
    'database_authenticated', 'database_temporal_state_observed', 'transaction_temporal_sources_selected',
    'trigger_phase_selected', 'script_slot_state_observed', 'script_arguments_selected',
    'provider_architectures_selected', 'trigger_eligibility_complete', 'trigger_selection_complete',
    'execution_order_complete', 'script_execution_plan_complete', 'script_policy_satisfied',
    'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')


def trigger_count_plan(observations, baseline, incoming):
    inventory = installed_version_inventory(observations, baseline)
    if not isinstance(incoming, list) or len(incoming) > 128:
        raise ValueError('trigger count incoming names exceed their profile')
    groups, files = {}, set()
    for entry in inventory['entries']:
        group = groups.setdefault(entry['name'], {'name': entry['name'], 'installed_instances': [], 'incoming_files': []})
        group['installed_instances'].append(entry['instance'])
    for entry in incoming:
        if (not isinstance(entry, dict) or not isinstance(entry.get('name'), str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', entry['name'])
                or not isinstance(entry.get('file'), str)
                or not re.fullmatch(r'packages/(?:0|[1-9][0-9]{0,2})\.rpm', entry['file'])
                or int(entry['file'][9:-4]) >= 128 or entry['file'] in files):
            raise ValueError('trigger count incoming name/file is unsupported or duplicated')
        files.add(entry['file'])
        group = groups.setdefault(entry['name'], {'name': entry['name'], 'installed_instances': [], 'incoming_files': []})
        group['incoming_files'].append(entry['file'])
    if len(groups) > TRIGGER_COUNT_NAMES:
        raise ValueError('trigger count unique names exceed their bound')
    rows = [{**groups[name], 'incoming_files': sorted(groups[name]['incoming_files']),
             'inventory_count': len(groups[name]['installed_instances'])} for name in sorted(groups)]
    encoded = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > TRIGGER_COUNT_BYTES:
        raise ValueError('trigger count rows exceed their serialization bound')
    return inventory, rows


def trigger_count_bind(lib):
    if (platform.machine() not in ('x86_64', 'aarch64') or C.sizeof(C.c_void_p) != 8
            or C.sizeof(C.c_ulong) != 8 or C.sizeof(C.c_int) != 4):
        raise ValueError('trigger count ABI is unsupported')
    api = {}
    for name, signature in {'rpmtsGetRdb': (C.c_void_p, C.c_void_p),
            'rpmtsGetDBMode': (C.c_int, C.c_void_p),
            'rpmdbCountPackages': (C.c_int, C.c_void_p, C.c_char_p)}.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('trigger count symbol is missing: ' + name) from error
        function.restype, function.argtypes = signature[0], signature[1:]; api[name] = function
    return api


def trigger_count_sample(api, transaction, rows):
    # The transaction remains live; GetRdb returns its borrowed database.
    database = api['rpmtsGetRdb'](transaction)
    if not database or database == transaction:
        raise ValueError('trigger count database is missing or aliases its transaction')
    if api['rpmtsGetDBMode'](transaction) != os.O_RDONLY:
        raise ValueError('trigger count database mode is not read-only')
    control = api['rpmdbCountPackages'](database, None)
    if type(control) is not int or control != -1:
        raise ValueError('trigger count NULL-name participation control failed')
    observed = []
    for row in rows:
        name = row['name'].encode('ascii'); buffer = C.create_string_buffer(name)
        count = api['rpmdbCountPackages'](database, buffer)
        if buffer.raw != name + b'\0':
            raise ValueError('trigger count native query changed its caller name')
        if type(count) is not int or not 0 <= count <= 32768 or count != row['inventory_count']:
            raise ValueError('trigger count native result differs from complete installed inventory')
        observed.append(count)
    if (api['rpmtsGetRdb'](transaction) != database
            or api['rpmtsGetDBMode'](transaction) != os.O_RDONLY):
        raise ValueError('trigger count borrowed database context changed')
    return database, observed


def trigger_count_receipt(inventory, rows, before, after):
    expected = [row['inventory_count'] for row in rows]
    if (not isinstance(before, list) or not isinstance(after, list)
            or any(type(value) is not int for value in (*before, *after))
            or before != expected or after != expected):
        raise ValueError('trigger count before/after samples differ from the complete inventory')
    observed = [{**row, 'native_before': first, 'native_after': second}
                for row, first, second in zip(rows, before, after)]
    encoded = json.dumps(observed, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > TRIGGER_COUNT_BYTES:
        raise ValueError('trigger count observation exceeds its serialization bound')
    return {'schema': 1, 'rows': observed, 'rows_bytes': len(encoded),
        'rows_sha256': hashlib.sha256(encoded).hexdigest(), 'names': len(rows), 'samples': 2,
        'null_name_controls': 2, 'native_count_calls': 2 * (len(rows) + 1),
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'count_inventory_correspondence_observed': True,
        'scope': 'CURRENT installed NAME-index counts bracketing qualified TEST ONLY; no phase correction or runtime script arguments',
        **{flag: False for flag in TRIGGER_COUNT_AUTHORITIES}}


def trigger_count_observe(proof, comparator_factory=None):
    proof = header_iteration_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, rows = trigger_count_plan({value['instance']: value for value in source['entries']},
                                         proof['baseline'], proof['effects']['incoming'])
    if inventory != source:
        raise ValueError('trigger count inventory differs from current qualified capture')
    expected = [row['inventory_count'] for row in rows]
    receipt = trigger_count_receipt(inventory, rows, expected, expected)
    observed = proof['effects']['installed_name_counts']
    # Equality alone would admit bools in integer positions; read the complete
    # typed receipt, including each full row and every authority declaration.
    if (not isinstance(observed, dict) or set(observed) != set(receipt)
            or any(type(observed[key]) is not type(value) for key, value in receipt.items())
            or not isinstance(observed['rows'], list) or len(observed['rows']) != len(receipt['rows'])
            or any(not isinstance(row, dict) or set(row) != set(wanted)
                   or any(type(row[key]) is not type(value) for key, value in wanted.items())
                   or any(type(value) is not int for value in row['installed_instances'])
                   or any(type(value) is not str for value in row['incoming_files'])
                   for row, wanted in zip(observed['rows'], receipt['rows']))
            or observed != receipt):
        raise ValueError('trigger count raw native receipt differs from complete current inventory')
    proof['trigger_count_observation'] = {**receipt,
        'header_iteration_sha256': proof['header_iteration_observation']['owners_sha256']}
    return proof

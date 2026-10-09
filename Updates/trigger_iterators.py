"""Observe CURRENT NAME-index traversal, not a future trigger-event iterator."""
import ctypes as C
import hashlib
import json
import os

trigger_iterators_projection = False
TRIGGER_ITERATOR_EXPORT_BYTES = 512 * 1024 * 1024
TRIGGER_ITERATOR_BYTES = 8 * 1024 * 1024
TRIGGER_ITERATOR_AUTHORITIES = ('headers_authenticated', 'native_library_identity_authenticated',
    'database_authenticated', 'database_temporal_state_observed', 'transaction_temporal_sources_selected',
    'trigger_phase_selected', 'runtime_iterator_selected', 'runtime_iterator_cardinality_observed',
    'script_slot_state_observed', 'script_arguments_selected', 'provider_architectures_selected',
    'trigger_eligibility_complete', 'trigger_selection_complete', 'execution_order_complete',
    'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied',
    'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')


def trigger_iterator_plan(observations, baseline, incoming):
    inventory, rows = trigger_count_plan(observations, baseline, incoming)
    if sum(entry['header_bytes'] for entry in inventory['entries']) > TRIGGER_ITERATOR_EXPORT_BYTES:
        raise ValueError('trigger iterator complete export work exceeds its bound')
    return inventory, rows


def trigger_iterator_bind(lib):
    api = trigger_count_bind(lib)
    if C.sizeof(C.c_uint) != 4:
        raise ValueError('trigger iterator uint32 ABI is unsupported')
    for name, signature in {'rpmdbInitIterator': (C.c_void_p, C.c_void_p, C.c_int, C.c_void_p, C.c_size_t),
            'rpmdbGetIteratorCount': (C.c_int, C.c_void_p),
            'rpmdbNextIterator': (C.c_void_p, C.c_void_p),
            'rpmdbGetIteratorOffset': (C.c_uint, C.c_void_p),
            'rpmdbFreeIterator': (C.c_void_p, C.c_void_p),
            'headerExport': (C.c_void_p, C.c_void_p, C.POINTER(C.c_uint))}.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('trigger iterator symbol is missing: ' + name) from error
        function.restype, function.argtypes = signature[0], signature[1:]; api[name] = function
    return api


def trigger_iterator_sample(api, free, transaction, inventory, rows):
    # The live transaction owns the database. rpmdbInitIterator adds its own
    # iterator reference; Header results are borrowed until the next Next/free.
    database = api['rpmtsGetRdb'](transaction)
    if not database or database == transaction or api['rpmtsGetDBMode'](transaction) != os.O_RDONLY:
        raise ValueError('trigger iterator database context is unsupported')
    control = api['rpmdbGetIteratorCount'](None)
    if (type(control) is not int or control != 0
            or api['rpmdbNextIterator'](None) is not None
            or api['rpmdbFreeIterator'](None) is not None):
        raise ValueError('trigger iterator NULL participation control failed')
    entries = {entry['instance']: entry for entry in inventory['entries']}
    observed, total = [], 0
    for row in rows:
        name = row['name'].encode('ascii'); buffer = C.create_string_buffer(name)
        caller = C.addressof(buffer)
        iterator = api['rpmdbInitIterator'](database, 1000, buffer, 0)
        if iterator in (transaction, database, caller):
            raise ValueError('trigger iterator result aliases a known nonowned base')
        try:
            if buffer.raw != name + b'\0':
                raise ValueError('trigger iterator changed its caller name')
            start = api['rpmdbGetIteratorCount'](iterator)
            if type(start) is not int or start != row['inventory_count'] or (start and not iterator):
                raise ValueError('trigger iterator advertised count differs from complete inventory')
            order, seen, expected_instances = [], set(), set(row['installed_instances'])
            for _ in range(start):
                header = api['rpmdbNextIterator'](iterator)
                if not header or header in (transaction, database, iterator, caller):
                    raise ValueError('trigger iterator borrowed Header is missing or aliases a known base')
                instance = api['rpmdbGetIteratorOffset'](iterator)
                if type(instance) is not int or instance not in expected_instances or instance in seen:
                    raise ValueError('trigger iterator instance is foreign or duplicated')
                size = C.c_uint(0); size_base = C.addressof(size)
                material = api['headerExport'](header, C.byref(size))
                if not material or material in (transaction, database, iterator, caller, header, size_base):
                    raise ValueError('trigger iterator export aliases a known nonowned base or is missing')
                try:
                    expected = entries[instance]
                    if size.value != expected['header_bytes'] or not 1 <= size.value <= 8 * 1024 * 1024:
                        raise ValueError('trigger iterator export length differs from captured Header')
                    total += size.value
                    if total > TRIGGER_ITERATOR_EXPORT_BYTES:
                        raise ValueError('trigger iterator export work exceeds its bound')
                    if hashlib.sha256(C.string_at(material, size.value)).hexdigest() != expected['header_sha256']:
                        raise ValueError('trigger iterator export differs from captured Header')
                finally:
                    free(material)
                order.append(instance)
                seen.add(instance)
            if api['rpmdbNextIterator'](iterator) is not None:
                raise ValueError('trigger iterator has an unexpected extra Header')
            end = api['rpmdbGetIteratorCount'](iterator)
            if (type(end) is not int or end != start or sorted(order) != row['installed_instances']
                    or buffer.raw != name + b'\0'):
                raise ValueError('trigger iterator terminal count/instances/caller correspondence failed')
            observed.append({'count_start': start, 'count_end': end, 'order': order,
                             'iterator_present': bool(iterator)})
        finally:
            if iterator and api['rpmdbFreeIterator'](iterator) is not None:
                raise ValueError('trigger iterator retirement did not return NULL')
            if buffer.raw != name + b'\0':
                raise ValueError('trigger iterator retirement changed its caller name')
    if (api['rpmtsGetRdb'](transaction) != database
            or api['rpmtsGetDBMode'](transaction) != os.O_RDONLY):
        raise ValueError('trigger iterator borrowed database context changed')
    return database, observed


def trigger_iterator_receipt(inventory, rows, before, after):
    if not isinstance(before, list) or not isinstance(after, list) or len(before) != len(rows) or len(after) != len(rows):
        raise ValueError('trigger iterator samples are incomplete')
    for sample in (before, after):
        for observed, row in zip(sample, rows):
            if (not isinstance(observed, dict) or set(observed) != {'count_start', 'count_end', 'order', 'iterator_present'}
                    or type(observed['count_start']) is not int or type(observed['count_end']) is not int
                    or type(observed['iterator_present']) is not bool or not isinstance(observed['order'], list)
                    or any(type(value) is not int for value in observed['order'])
                    or observed['count_start'] != row['inventory_count'] or observed['count_end'] != row['inventory_count']
                    or sorted(observed['order']) != row['installed_instances']
                    or (row['inventory_count'] and not observed['iterator_present'])):
                raise ValueError('trigger iterator typed samples differ from complete installed inventory')
    observed = [{**row, 'before': first, 'after': second} for row, first, second in zip(rows, before, after)]
    encoded = json.dumps(observed, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > TRIGGER_ITERATOR_BYTES:
        raise ValueError('trigger iterator observation exceeds its serialization bound')
    owned = sum(value['iterator_present'] for sample in (before, after) for value in sample)
    # Per sample: four database/mode reads, three NULL controls; each name has
    # init/two Count/terminal Next, plus one free if nonNULL, and Next/offset/export
    # for each Header. libc export frees and all inherited APIs are separate.
    return {'schema': 1, 'rows': observed, 'rows_bytes': len(encoded), 'rows_sha256': hashlib.sha256(encoded).hexdigest(),
        'names': len(rows), 'samples': 2, 'headers_per_sample': inventory['headers'],
        'iterator_init_calls': 2 * len(rows), 'owned_iterator_retirements': owned,
        'header_export_calls': 2 * inventory['headers'], 'null_controls': 6,
        'new_rpm_api_calls': 14 + 8 * len(rows) + owned + 6 * inventory['headers'],
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'count_and_complete_traversal_correspondence_observed': True,
        'borrowed_header_exports_observed': bool(inventory['headers']),
        'scope': 'CURRENT direct NAME-index count/traversal/export correspondence bracketing qualified TEST ONLY; not the future PSM iterator',
        **{flag: False for flag in TRIGGER_ITERATOR_AUTHORITIES}}


def trigger_iterator_equal(observed, expected):
    if type(observed) is not type(expected): return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(trigger_iterator_equal(observed[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(trigger_iterator_equal(value, wanted) for value, wanted in zip(observed, expected))
    return observed == expected


def trigger_iterator_observe(proof, comparator_factory=None):
    proof = trigger_argument_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, rows = trigger_iterator_plan({entry['instance']: entry for entry in source['entries']},
                                           proof['baseline'], proof['effects']['incoming'])
    if inventory != source:
        raise ValueError('trigger iterator inventory differs from current qualified capture')
    raw = proof['effects']['installed_name_iterators']
    if not isinstance(raw, dict) or not isinstance(raw.get('rows'), list) or len(raw['rows']) != len(rows):
        raise ValueError('trigger iterator raw receipt is missing complete rows')
    before, after = [], []
    for value in raw['rows']:
        if not isinstance(value, dict): raise ValueError('trigger iterator raw row is unsupported')
        before.append(value['before']); after.append(value['after'])
    receipt = trigger_iterator_receipt(inventory, rows, before, after)
    if not trigger_iterator_equal(raw, receipt):
        raise ValueError('trigger iterator raw receipt differs from complete current inventory')
    proof['trigger_iterator_observation'] = {**receipt,
        'current_name_counts_sha256': proof['trigger_count_observation']['rows_sha256'],
        'conditional_arguments_sha256': proof['trigger_argument_observation']['pairs_sha256']}
    return proof

"""CURRENT ordered transaction elements/borrowed links, not future PSM state."""
import ctypes as C
import hashlib
import json
import os
import re

transaction_elements_projection = False
TRANSACTION_ELEMENT_LIMIT = 32768 + 128
TRANSACTION_ELEMENT_BYTES = 8 * 1024 * 1024
TRANSACTION_ELEMENT_AUTHORITIES = (*TRIGGER_COUNT_AUTHORITIES,
    'transaction_goal_selected', 'runtime_count_correction_observed',
    'runtime_dependency_links_observed', 'script_arguments_observed')


def transaction_element_plan(observations, baseline, incoming, removals):
    inventory, _ = trigger_count_plan(observations, baseline, incoming)
    installed = {entry['instance']: entry for entry in inventory['entries']}
    if not isinstance(removals, list) or len(incoming) + len(removals) > TRANSACTION_ELEMENT_LIMIT:
        raise ValueError('transaction element complete plan exceeds its bound')
    additions, erasures = {}, {}
    for value in incoming:
        owner = {field: value[field] for field in ('file', 'sha256', 'bytes', 'name', 'nevra', 'header_sha256', 'header_bytes')}
        for field in ('sha256', 'header_sha256'):
            if not isinstance(owner[field], str) or not re.fullmatch(r'[0-9a-f]{64}', owner[field]):
                raise ValueError('transaction element incoming digest is unsupported')
        if (type(owner['bytes']) is not int or not 1 <= owner['bytes'] <= 2**63 - 1
                or type(owner['header_bytes']) is not int or not 1 <= owner['header_bytes'] <= 8 * 1024 * 1024
                or not isinstance(owner['nevra'], str) or not re.fullmatch(r'[!-~]{1,1024}', owner['nevra'])):
            raise ValueError('transaction element incoming identity is unsupported')
        additions[owner['file']] = {'kind': 'incoming', **owner}
    for value in removals:
        instance = value['instance']
        if (type(instance) is not int or instance not in installed or instance in erasures
                or any(value[field] != expected for field, expected in installed[instance].items())):
            raise ValueError('transaction element removal differs from complete installed inventory')
        erasures[instance] = {'kind': 'removed', **installed[instance]}
    plan = {'incoming': additions, 'removals': erasures, 'removal_order': list(erasures)}
    if len(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode('ascii')) > TRANSACTION_ELEMENT_BYTES:
        raise ValueError('transaction element plan exceeds its serialization bound')
    return inventory, plan


def transaction_element_bind(lib):
    api = trigger_count_bind(lib)
    if C.sizeof(C.c_uint) != 4:
        raise ValueError('transaction element uint32 ABI is unsupported')
    for name, signature in {
            'rpmtsNElements': (C.c_int, C.c_void_p),
            'rpmtsElement': (C.c_void_p, C.c_void_p, C.c_int),
            'rpmteType': (C.c_uint, C.c_void_p),
            'rpmteN': (C.c_char_p, C.c_void_p),
            'rpmteNEVRA': (C.c_char_p, C.c_void_p),
            'rpmteKey': (C.c_char_p, C.c_void_p),
            'rpmteDBInstance': (C.c_uint, C.c_void_p),
            'rpmteDependsOn': (C.c_void_p, C.c_void_p)}.items():
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('transaction element symbol is missing: ' + name) from error
        function.restype, function.argtypes = signature[0], signature[1:]; api[name] = function
    return api


def transaction_element_sample(api, transaction, plan, snapshots):
    # All TS/DB/TE/dependency handles are borrowed. Do not acquire/free them.
    # In particular rpmteDependsOn is NOT NULL-safe in the pinned source.
    database = api['rpmtsGetRdb'](transaction)
    if (type(database) is not int or database <= 0 or database == transaction
            or api['rpmtsGetDBMode'](transaction) != os.O_RDONLY):
        raise ValueError('transaction element borrowed database context is unsupported')
    controls = (api['rpmtsNElements'](None), api['rpmteType'](None), api['rpmteDBInstance'](None))
    if (any(type(value) is not int for value in controls) or controls != (0, 2**32 - 1, 0)
            or api['rpmtsElement'](None, 0) is not None):
        raise ValueError('transaction element NULL participation control failed')
    count = api['rpmtsNElements'](transaction)
    if type(count) is not int or count != len(plan['incoming']) + len(plan['removals']) or not 0 <= count <= TRANSACTION_ELEMENT_LIMIT:
        raise ValueError('transaction element count differs from complete plan')
    if api['rpmtsElement'](transaction, -1) is not None or api['rpmtsElement'](transaction, count) is not None:
        raise ValueError('transaction element index boundary control failed')
    handles, seen = [], set()
    for index in range(count):
        handle = api['rpmtsElement'](transaction, index)
        if type(handle) is not int or handle <= 0 or handle in (transaction, database) or handle in seen:
            raise ValueError('transaction element borrowed handle is missing, aliases a known base or is duplicated')
        handles.append(handle); seen.add(handle)
    positions = {handle: index for index, handle in enumerate(handles)}
    samples = []
    for _ in range(2):
        rows = []
        for index, handle in enumerate(handles):
            kind, name, nevra = api['rpmteType'](handle), api['rpmteN'](handle), api['rpmteNEVRA'](handle)
            dependency = api['rpmteDependsOn'](handle)
            if type(kind) is not int or kind not in (1, 2):
                raise ValueError('transaction element kind is unsupported')
            if kind == 1:
                snapshot = api['rpmteKey'](handle)
                owner = plan['incoming'].get(snapshots.get(snapshot))
            else:
                instance = api['rpmteDBInstance'](handle)
                owner = plan['removals'].get(instance) if type(instance) is int else None
            if (owner is None or name != owner['name'].encode('ascii') or nevra != owner['nevra'].encode('ascii')):
                raise ValueError('transaction element identity differs from its SAME captured owner')
            if dependency is not None and (type(dependency) is not int or dependency not in positions):
                raise ValueError('transaction element dependency is outside the complete borrowed handle set')
            rows.append({'position': index, 'owner': owner,
                         'depends_on': None if dependency is None else positions[dependency]})
        transaction_element_rows(plan, rows)
        samples.append(rows)
    if (samples[0] != samples[1] or api['rpmtsNElements'](transaction) != count
            or any(api['rpmtsElement'](transaction, index) != handle for index, handle in enumerate(handles))
            or api['rpmtsGetRdb'](transaction) != database or api['rpmtsGetDBMode'](transaction) != os.O_RDONLY):
        raise ValueError('transaction element complete readback/context changed')
    return database, handles, samples[0]


def transaction_element_rows(plan, rows):
    if not isinstance(rows, list) or len(rows) != len(plan['incoming']) + len(plan['removals']):
        raise ValueError('transaction element rows are incomplete')
    additions, removals = [], []
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or set(row) != {'position', 'owner', 'depends_on'}
                or type(row['position']) is not int or row['position'] != index or not isinstance(row['owner'], dict)):
            raise ValueError('transaction element row is unsupported or unordered')
        owner, dependency = row['owner'], row['depends_on']
        if owner.get('kind') == 'incoming':
            expected = plan['incoming'].get(owner.get('file')); additions.append(owner.get('file'))
            if dependency is not None: raise ValueError('transaction element incoming dependency is unsupported')
        elif owner.get('kind') == 'removed':
            instance = owner.get('instance')
            expected = plan['removals'].get(instance) if type(instance) is int else None; removals.append(instance)
        else: raise ValueError('transaction element owner kind is unsupported')
        if not trigger_iterator_equal(owner, expected):
            raise ValueError('transaction element row differs from its complete captured owner')
        if dependency is not None and (type(dependency) is not int or not 0 <= dependency < len(rows)):
            raise ValueError('transaction element dependency position is unsupported')
    if sorted(additions) != sorted(plan['incoming']) or removals != plan['removal_order']:
        raise ValueError('transaction element complete membership/removal order differs')
    for row in rows:
        dependency = row['depends_on']
        if dependency is not None and rows[dependency]['owner']['kind'] != 'incoming':
            raise ValueError('transaction element removal dependency is not an incoming element')


def transaction_element_receipt(inventory, plan, before, after):
    transaction_element_rows(plan, before); transaction_element_rows(plan, after)
    if not trigger_iterator_equal(before, after):
        raise ValueError('transaction element ordered observations changed across TEST')
    encoded = json.dumps(before, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > TRANSACTION_ELEMENT_BYTES:
        raise ValueError('transaction element observation exceeds its serialization bound')
    links = [{'removed_position': row['position'], 'incoming_position': row['depends_on'],
              'same_package_name': row['owner']['name'] == before[row['depends_on']]['owner']['name']}
             for row in before if row['depends_on'] is not None]
    return {'schema': 1, 'before': before, 'after': after, 'elements': len(before),
        'dependency_links': links, 'rows_bytes': len(encoded), 'rows_sha256': hashlib.sha256(encoded).hexdigest(),
        'samples': 2, 'readback_passes_per_sample': 2, 'null_controls': 8, 'index_boundary_controls': 4,
        'new_rpm_api_calls': 24 + 24 * len(before),
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'current_ordered_elements_observed': bool(before), 'current_dependency_links_observed': bool(links),
        'scope': 'CURRENT ordered TS elements and borrowed dependency links bracketing qualified TEST only; incoming DB instances and future PSM phase/state/arguments remain UNOBSERVED',
        **{flag: False for flag in TRANSACTION_ELEMENT_AUTHORITIES}}


def transaction_element_observe(proof, comparator_factory=None):
    proof = trigger_walk_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, plan = transaction_element_plan({entry['instance']: entry for entry in source['entries']},
        proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
    if not trigger_iterator_equal(inventory, source):
        raise ValueError('transaction element inventory differs from current qualified capture')
    raw = proof['effects']['ordered_transaction_elements']
    if not isinstance(raw, dict): raise ValueError('transaction element raw observation is missing')
    receipt = transaction_element_receipt(inventory, plan, raw['before'], raw['after'])
    if not trigger_iterator_equal(raw, receipt):
        raise ValueError('transaction element raw receipt differs from rebuilt correspondence')
    proof['transaction_element_observation'] = receipt
    return proof

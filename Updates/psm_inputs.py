"""CURRENT binary/source getter correspondence, not future PSM continuity."""
import ctypes as C
import hashlib
import json
import os

psm_inputs_projection = False
PSM_INPUT_BYTES = 8 * 1024 * 1024
PSM_INPUT_AUTHORITIES = (*TRANSACTION_ELEMENT_AUTHORITIES,
    'binary_psm_branch_observed', 'runtime_psm_created',
    'package_script_arguments_selected', 'package_scripts_executed',
    'source_header_classification_authenticated', 'runtime_binary_state_continuous',
    'source_package_policy_satisfied')


def psm_input_bind(lib):
    api = transaction_element_bind(lib)
    try: function = lib.rpmteIsSource
    except AttributeError as error: raise ValueError('PSM input rpmteIsSource symbol is missing') from error
    function.restype, function.argtypes = C.c_int, (C.c_void_p,)
    api['rpmteIsSource'] = function
    return api


def psm_input_rows(plan, elements, rows):
    transaction_element_rows(plan, elements)
    if not isinstance(rows, list) or len(rows) != len(elements):
        raise ValueError('PSM input complete source rows are missing')
    for element, row in zip(elements, rows):
        if (not isinstance(row, dict) or set(row) != {'element', 'is_source'}
                or not trigger_iterator_equal(row['element'], element)
                or type(row['is_source']) is not int or row['is_source'] not in (0, 1)):
            raise ValueError('PSM input source row differs from the complete current element')


def psm_input_sample(api, transaction, database, handles, plan, elements):
    # Borrowed TS/DB/TE bases remain under the existing live TS lifetime.
    # No allocation, reference acquisition, ownership transfer or free here.
    transaction_element_rows(plan, elements)
    if (type(transaction) is not int or transaction <= 0 or type(database) is not int
            or database <= 0 or database == transaction or not isinstance(handles, list)
            or len(handles) != len(elements) or len(handles) > TRANSACTION_ELEMENT_LIMIT
            or any(type(handle) is not int or handle <= 0 or handle in (transaction, database) for handle in handles)
            or len(set(handles)) != len(handles)):
        raise ValueError('PSM input complete borrowed handles are unsupported')
    def context():
        count = api['rpmtsNElements'](transaction)
        current, mode = api['rpmtsGetRdb'](transaction), api['rpmtsGetDBMode'](transaction)
        if (type(current) is not int or current != database or type(mode) is not int or mode != os.O_RDONLY
                or type(count) is not int or count != len(handles)):
            raise ValueError('PSM input borrowed context/order differs')
        order = [api['rpmtsElement'](transaction, index) for index in range(len(handles))]
        if any(type(handle) is not int for handle in order) or order != handles:
            raise ValueError('PSM input borrowed context/order differs')
    context()
    control = api['rpmteIsSource'](None)
    if type(control) is not int or control != 0:
        raise ValueError('PSM input NULL getter control failed')
    samples = []
    for _ in range(2):
        rows = [{'element': element, 'is_source': api['rpmteIsSource'](handle)}
                for handle, element in zip(handles, elements)]
        psm_input_rows(plan, elements, rows); samples.append(rows)
    if not trigger_iterator_equal(samples[0], samples[1]):
        raise ValueError('PSM input complete source readback changed')
    context()
    return samples[0]


def psm_input_receipt(inventory, plan, elements, before, after):
    rebuilt = transaction_element_receipt(inventory, plan, elements['before'], elements['after'])
    if not trigger_iterator_equal(elements, rebuilt):
        raise ValueError('PSM input ordered element receipt differs')
    psm_input_rows(plan, elements['before'], before); psm_input_rows(plan, elements['after'], after)
    if not trigger_iterator_equal(before, after):
        raise ValueError('PSM input source observations changed across TEST')
    encoded = json.dumps(before, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > PSM_INPUT_BYTES:
        raise ValueError('PSM input source observation exceeds its serialization bound')
    return {'schema': 1, 'before': before, 'after': after, 'elements': len(before),
        'rows_bytes': len(encoded), 'rows_sha256': hashlib.sha256(encoded).hexdigest(),
        'samples': 2, 'source_readback_passes_per_sample': 2, 'null_controls': 2,
        'new_rpm_api_calls': 14 + 8 * len(before), 'new_source_getter_calls': 2 + 4 * len(before),
        'current_source_flags_observed': bool(before),
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'scope': 'CURRENT rpmteIsSource declarations on SAME ordered borrowed elements bracketing qualified TEST; NULL-zero is not positive source participation, authenticity or future binary PSM continuity',
        **{flag: False for flag in PSM_INPUT_AUTHORITIES}}


def psm_input_observe(proof, comparator_factory=None):
    proof = psm_goal_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, plan = transaction_element_plan({row['instance']: row for row in source['entries']},
        proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
    raw = proof['effects']['current_psm_inputs']
    if not isinstance(raw, dict): raise ValueError('PSM input raw source observation is missing')
    receipt = psm_input_receipt(inventory, plan, proof['effects']['ordered_transaction_elements'], raw['before'], raw['after'])
    if not trigger_iterator_equal(raw, receipt):
        raise ValueError('PSM input raw source receipt differs from rebuilt correspondence')
    if any(row['is_source'] for row in receipt['before']):
        raise ValueError('CURRENT source transaction element defers the binary PSM prerequisite')
    proof['psm_input_observation'] = {**receipt, 'current_binary_elements_observed': bool(receipt['before']),
        'fresh_runtime_binary_branch_required': True, **{flag: False for flag in PSM_INPUT_AUTHORITIES}}
    return proof

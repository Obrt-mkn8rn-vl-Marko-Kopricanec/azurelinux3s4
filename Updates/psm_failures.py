"""CURRENT failure getter correspondence, not future processing eligibility."""
import ctypes as C
import hashlib
import json
import os

psm_failures_projection = False
PSM_FAILURE_BYTES = 8 * 1024 * 1024
PSM_FAILURE_AUTHORITIES = (*PSM_INPUT_AUTHORITIES,
    'transaction_failure_state_authenticated', 'runtime_failure_state_continuous',
    'package_header_opened_for_processing', 'failure_propagation_executed',
    'transaction_processing_eligible')


def psm_failure_bind(lib):
    api = transaction_element_bind(lib)
    try: function = lib.rpmteFailed
    except AttributeError as error: raise ValueError('PSM failure rpmteFailed symbol is missing') from error
    function.restype, function.argtypes = C.c_int, (C.c_void_p,)
    api['rpmteFailed'] = function
    return api


def psm_failure_rows(plan, elements, rows):
    transaction_element_rows(plan, elements)
    if not isinstance(rows, list) or len(rows) != len(elements):
        raise ValueError('PSM failure complete failure rows are missing')
    for element, row in zip(elements, rows):
        if (not isinstance(row, dict) or set(row) != {'element', 'failure_count'}
                or not trigger_iterator_equal(row['element'], element)
                or type(row['failure_count']) is not int or not 0 <= row['failure_count'] <= 2**31 - 1):
            raise ValueError('PSM failure row differs from the complete current element or signed count')


def psm_failure_sample(api, transaction, database, handles, plan, elements):
    # All handles remain borrowed under the existing TS lifetime; no new free.
    transaction_element_rows(plan, elements)
    if (type(transaction) is not int or transaction <= 0 or type(database) is not int
            or database <= 0 or database == transaction or not isinstance(handles, list)
            or len(handles) != len(elements) or len(handles) > TRANSACTION_ELEMENT_LIMIT
            or any(type(handle) is not int or handle <= 0 or handle in (transaction, database) for handle in handles)
            or len(set(handles)) != len(handles)):
        raise ValueError('PSM failure complete borrowed handles are unsupported')
    def context():
        count = api['rpmtsNElements'](transaction)
        current, mode = api['rpmtsGetRdb'](transaction), api['rpmtsGetDBMode'](transaction)
        if (type(current) is not int or current != database or type(mode) is not int or mode != os.O_RDONLY
                or type(count) is not int or count != len(handles)):
            raise ValueError('PSM failure borrowed context/order differs')
        order = [api['rpmtsElement'](transaction, index) for index in range(len(handles))]
        if any(type(handle) is not int for handle in order) or order != handles:
            raise ValueError('PSM failure borrowed context/order differs')
    context()
    control = api['rpmteFailed'](None)
    if type(control) is not int or control != -1:
        raise ValueError('PSM failure NULL-minus-one getter control failed')
    samples = []
    for _ in range(2):
        rows = [{'element': element, 'failure_count': api['rpmteFailed'](handle)}
                for handle, element in zip(handles, elements)]
        psm_failure_rows(plan, elements, rows); samples.append(rows)
    if not trigger_iterator_equal(samples[0], samples[1]):
        raise ValueError('PSM failure complete failure readback changed')
    context()
    return samples[0]


def psm_failure_receipt(inventory, plan, elements, before, after):
    rebuilt = transaction_element_receipt(inventory, plan, elements['before'], elements['after'])
    if not trigger_iterator_equal(elements, rebuilt):
        raise ValueError('PSM failure ordered element receipt differs')
    psm_failure_rows(plan, elements['before'], before); psm_failure_rows(plan, elements['after'], after)
    if not trigger_iterator_equal(before, after):
        raise ValueError('PSM failure observations changed across TEST')
    encoded = json.dumps(before, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > PSM_FAILURE_BYTES:
        raise ValueError('PSM failure observation exceeds its serialization bound')
    return {'schema': 1, 'before': before, 'after': after, 'elements': len(before),
        'rows_bytes': len(encoded), 'rows_sha256': hashlib.sha256(encoded).hexdigest(),
        'samples': 2, 'failure_readback_passes_per_sample': 2, 'null_controls': 2,
        'new_rpm_api_calls': 14 + 8 * len(before), 'new_failure_getter_calls': 2 + 4 * len(before),
        'current_failure_counts_observed': bool(before),
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'scope': 'CURRENT rpmteFailed counts on SAME ordered borrowed elements bracketing qualified TEST; NULL-minus-one is not positive failed-element participation, authenticity or future processing eligibility',
        **{flag: False for flag in PSM_FAILURE_AUTHORITIES}}


def psm_failure_observe(proof, comparator_factory=None):
    proof = psm_route_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, plan = transaction_element_plan({row['instance']: row for row in source['entries']},
        proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
    raw = proof['effects']['current_psm_failures']
    if not isinstance(raw, dict): raise ValueError('PSM failure raw observation is missing')
    receipt = psm_failure_receipt(inventory, plan, proof['effects']['ordered_transaction_elements'], raw['before'], raw['after'])
    if not trigger_iterator_equal(raw, receipt):
        raise ValueError('PSM failure raw receipt differs from rebuilt correspondence')
    if any(row['failure_count'] for row in receipt['before']):
        raise ValueError('CURRENT failed transaction element defers the processing prerequisite')
    proof['psm_failure_observation'] = {**receipt, 'current_zero_failure_counts_observed': bool(receipt['before']),
        'fresh_runtime_failure_state_required': True, **{flag: False for flag in PSM_FAILURE_AUTHORITIES}}
    return proof

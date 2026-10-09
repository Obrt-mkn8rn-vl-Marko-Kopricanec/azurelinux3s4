"""CURRENT verification-mask transition, not authenticated or future PSM state."""
import ctypes as C
import hashlib
import json
import os

psm_verification_projection = False
PSM_VERIFICATION_BYTES = 8 * 1024 * 1024
PSM_UNVERIFIED = 1 << 30
PSM_VERIFICATION_AUTHORITIES = (*PSM_FAILURE_AUTHORITIES,
    'transaction_verification_state_authenticated', 'verification_algorithms_approved',
    'installed_header_verification_observed', 'runtime_verification_state_continuous',
    'future_package_verification_complete')


def psm_verification_bind(lib):
    api = transaction_element_bind(lib)
    for name, result in (('rpmteVerified', C.c_int), ('rpmtsVSFlags', C.c_uint),
                         ('rpmtsVfyFlags', C.c_uint), ('rpmtsVfyLevel', C.c_int)):
        try: function = getattr(lib, name)
        except AttributeError as error: raise ValueError('PSM verification symbol is missing: ' + name) from error
        function.restype, function.argtypes = result, (C.c_void_p,)
        api[name] = function
    return api


def psm_verification_rows(plan, elements, rows):
    transaction_element_rows(plan, elements)
    if not isinstance(rows, list) or len(rows) != len(elements):
        raise ValueError('PSM verification complete rows are missing')
    for element, row in zip(elements, rows):
        if (not isinstance(row, dict) or set(row) != {'element', 'verification_mask'}
                or not trigger_iterator_equal(row['element'], element)
                or type(row['verification_mask']) is not int
                or row['verification_mask'] not in (0, 1, 2, 3, PSM_UNVERIFIED)):
            raise ValueError('PSM verification row differs from the complete current element or supported mask')


def psm_verification_sample(api, transaction, database, handles, plan, elements):
    # Borrow existing TS/DB/TE handles only; no new allocation, link or free.
    transaction_element_rows(plan, elements)
    if (type(transaction) is not int or transaction <= 0 or type(database) is not int
            or database <= 0 or database == transaction or not isinstance(handles, list)
            or len(handles) != len(elements) or len(handles) > TRANSACTION_ELEMENT_LIMIT
            or any(type(handle) is not int or handle <= 0 or handle in (transaction, database) for handle in handles)
            or len(set(handles)) != len(handles)):
        raise ValueError('PSM verification complete borrowed handles are unsupported')
    def context():
        count = api['rpmtsNElements'](transaction)
        current, mode = api['rpmtsGetRdb'](transaction), api['rpmtsGetDBMode'](transaction)
        policy = (api['rpmtsVSFlags'](transaction), api['rpmtsVfyFlags'](transaction), api['rpmtsVfyLevel'](transaction))
        if (type(current) is not int or current != database or type(mode) is not int or mode != os.O_RDONLY
                or type(count) is not int or count != len(handles)
                or any(type(value) is not int for value in policy) or policy != (0, 0, 3)):
            raise ValueError('PSM verification borrowed context or digest/signature policy differs')
        order = [api['rpmtsElement'](transaction, index) for index in range(len(handles))]
        if any(type(handle) is not int for handle in order) or order != handles:
            raise ValueError('PSM verification borrowed element order differs')
    context()
    controls = tuple(api[name](None) for name in ('rpmteVerified', 'rpmtsVSFlags', 'rpmtsVfyFlags', 'rpmtsVfyLevel'))
    if any(type(value) is not int for value in controls) or controls != (0, 0, 0, 0):
        raise ValueError('PSM verification NULL-zero getter controls failed')
    samples = []
    for _ in range(2):
        rows = [{'element': element, 'verification_mask': api['rpmteVerified'](handle)}
                for handle, element in zip(handles, elements)]
        psm_verification_rows(plan, elements, rows); samples.append(rows)
    if not trigger_iterator_equal(samples[0], samples[1]):
        raise ValueError('PSM verification complete mask readback changed')
    context()
    return samples[0]


def psm_verification_receipt(inventory, plan, elements, before, after):
    rebuilt = transaction_element_receipt(inventory, plan, elements['before'], elements['after'])
    if not trigger_iterator_equal(elements, rebuilt):
        raise ValueError('PSM verification ordered element receipt differs')
    psm_verification_rows(plan, elements['before'], before); psm_verification_rows(plan, elements['after'], after)
    encoded = json.dumps({'before': before, 'after': after}, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > PSM_VERIFICATION_BYTES:
        raise ValueError('PSM verification observation exceeds its serialization bound')
    return {'schema': 1, 'before': before, 'after': after, 'elements': len(before),
        'rows_bytes': len(encoded), 'rows_sha256': hashlib.sha256(encoded).hexdigest(),
        'samples': 2, 'mask_readback_passes_per_sample': 2, 'null_controls': 8,
        'verification_policy': {'header_flags': 0, 'package_flags': 0, 'required_types': 3},
        'new_rpm_api_calls': 32 + 8 * len(before), 'new_verification_getter_calls': 2 + 4 * len(before),
        'current_verification_masks_observed': bool(before),
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'scope': 'CURRENT rpmteVerified masks on SAME ordered borrowed elements before/after qualified TEST; masks and NULL controls are native declarations, not cryptographic authentication or future processing eligibility',
        **{flag: False for flag in PSM_VERIFICATION_AUTHORITIES}}


def psm_verification_observe(proof, comparator_factory=None):
    proof = psm_failure_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, plan = transaction_element_plan({row['instance']: row for row in source['entries']},
        proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
    raw = proof['effects']['current_psm_verification']
    if not isinstance(raw, dict): raise ValueError('PSM verification raw observation is missing')
    receipt = psm_verification_receipt(inventory, plan, proof['effects']['ordered_transaction_elements'], raw['before'], raw['after'])
    if not trigger_iterator_equal(raw, receipt):
        raise ValueError('PSM verification raw receipt differs from rebuilt correspondence')
    if any(row['verification_mask'] != PSM_UNVERIFIED for row in receipt['before']):
        raise ValueError('PSM verification fresh unverified element prerequisite differs')
    for row in receipt['after']:
        expected = 3 if row['element']['owner']['kind'] == 'incoming' else PSM_UNVERIFIED
        if row['verification_mask'] != expected:
            raise ValueError('PSM verification post-TEST incoming digest/signature or unverified removal prerequisite differs')
    proof['psm_verification_observation'] = {**receipt,
        'current_incoming_digest_and_signature_masks_observed': bool(plan['incoming']),
        'fresh_runtime_verification_required': True, **{flag: False for flag in PSM_VERIFICATION_AUTHORITIES}}
    return proof

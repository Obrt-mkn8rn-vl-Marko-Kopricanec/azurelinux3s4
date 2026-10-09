"""Conditional binary PSM arguments with CURRENT counts/links held fixed."""
import hashlib
import json

PSM_GOALS = ('PKG_INSTALL', 'PKG_PRETRANS', 'PKG_ERASE', 'PKG_VERIFY', 'PKG_POSTTRANS')
PSM_GOAL_CASES = 65536
PSM_GOAL_BYTES = 8 * 1024 * 1024
PSM_GOAL_AUTHORITIES = (*TRANSACTION_ELEMENT_AUTHORITIES,
    'binary_psm_branch_observed', 'runtime_psm_created',
    'package_script_arguments_selected', 'package_scripts_executed')


def psm_goal_case(goal, count, linked):
    if (type(goal) is not str or goal not in PSM_GOALS
            or type(count) is not int or not 0 <= count <= 32768 or type(linked) is not bool):
        raise ValueError('PSM goal hypothetical operands are unsupported')
    # isUpdate is existential over removed TE links, with no package-name test.
    # These formulas apply ONLY if rpmteIsSource is false at PSM construction.
    if goal in ('PKG_INSTALL', 'PKG_PRETRANS'):
        argument, correction, update = count + 1, 0, None
    elif goal == 'PKG_ERASE':
        argument, correction, update = count - 1, -1, None
    else:
        update = int(linked)
        argument, correction = count + update, 0
    return {'goal': goal, 'conditional_package_script_arg': argument,
            'conditional_count_correction': correction, 'conditional_update_increment': update}


def psm_goal_forecast(inventory, plan, counts, elements):
    # Rebuild complete correspondence, not a previous positive forecast receipt.
    baseline = {'headers': inventory['headers'], 'sha256': inventory['baseline_sha256']}
    observations = {row['instance']: row for row in inventory['entries']}
    admitted_inventory, admitted_plan = transaction_element_plan(observations, baseline,
        list(plan['incoming'].values()), [plan['removals'][instance] for instance in plan['removal_order']])
    if (not trigger_iterator_equal(inventory, admitted_inventory)
            or not trigger_iterator_equal(plan, admitted_plan)):
        raise ValueError('PSM goal complete inventory/element plan differs')
    _, names = trigger_count_plan(observations, baseline, list(plan['incoming'].values()))
    expected_counts = [row['inventory_count'] for row in names]
    admitted_counts = trigger_count_receipt(inventory, names, expected_counts, expected_counts)
    admitted_elements = transaction_element_receipt(inventory, plan, elements['before'], elements['after'])
    if (not trigger_iterator_equal(counts, admitted_counts)
            or not trigger_iterator_equal(elements, admitted_elements)):
        raise ValueError('PSM goal complete current count/element receipt differs')
    case_count = 2 * len(elements['before']) * len(PSM_GOALS)
    if case_count > PSM_GOAL_CASES:
        raise ValueError('PSM goal hypothetical case count exceeds its bound')
    current_counts = {row['name']: row['inventory_count'] for row in names}
    records, encoded, size = [], [], 2
    for sample in ('before', 'after'):
        rows = elements[sample]
        links = {}
        for row in rows:
            if row['depends_on'] is not None:
                links.setdefault(row['depends_on'], []).append(row['position'])
        for row in rows:
            positions = links.get(row['position'], [])
            record = {'sample': sample, 'position': row['position'], 'owner': row['owner'],
                'current_installed_name_count': current_counts[row['owner']['name']],
                'linked_removed_positions': positions, 'current_removed_link_present': bool(positions),
                'conditional_binary_goals': [psm_goal_case(goal, current_counts[row['owner']['name']], bool(positions))
                                             for goal in PSM_GOALS]}
            data = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('ascii')
            size += len(data) + bool(records)
            if size > PSM_GOAL_BYTES:
                raise ValueError('PSM goal hypothetical matrix exceeds its serialization bound')
            records.append(record); encoded.append(data)
    material = b'[' + b','.join(encoded) + b']'
    if len(material) != size: raise ValueError('PSM goal matrix serialization differs from its bound')
    count_bytes = json.dumps(counts, sort_keys=True, separators=(',', ':')).encode('ascii')
    element_bytes = json.dumps(elements, sort_keys=True, separators=(',', ':')).encode('ascii')
    return {'schema': 1, 'rows': records, 'rows_bytes': size, 'rows_sha256': hashlib.sha256(material).hexdigest(),
        'elements_per_sample': len(elements['before']), 'current_samples': 2, 'hypothetical_goal_cases': case_count,
        'current_counts_receipt_sha256': hashlib.sha256(count_bytes).hexdigest(),
        'current_elements_receipt_sha256': hashlib.sha256(element_bytes).hexdigest(),
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'conditional_goals_forecast': bool(records), 'new_rpm_api_calls': 0,
        'fresh_runtime_count_and_links_required': True, 'fresh_runtime_binary_branch_required': True,
        'scope': 'UNSELECTED binary PSM goal formulas ONLY, if CURRENT counts/links remain fixed; no temporal PSM, scripts, trigger arguments, database evolution or source-package branch observation',
        **{flag: False for flag in PSM_GOAL_AUTHORITIES}}


def psm_goal_observe(proof, comparator_factory=None):
    proof = transaction_element_observe(proof, comparator_factory=comparator_factory)
    source = proof['effects']['installed_versions']
    inventory, plan = transaction_element_plan({row['instance']: row for row in source['entries']},
        proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
    proof['psm_goal_observation'] = psm_goal_forecast(inventory, plan,
        proof['effects']['installed_name_counts'], proof['effects']['ordered_transaction_elements'])
    return proof

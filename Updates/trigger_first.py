"""Forecast pair-first condition/slot behavior, without selecting runtime events."""
import hashlib
import json

TRIGGER_FIRST_PAIR_LIMIT = 16384
TRIGGER_FIRST_PHASE_LIMIT = 65536
TRIGGER_FIRST_ROW_WORK = 131072


def trigger_first_case(rows, phase, marked=()):
    phases = dict(TRIGGER_SOURCE_PHASES)
    if type(phase) is not int or phase not in phases:
        raise ValueError('trigger first hypothetical phase is unsupported')
    if (not isinstance(rows, list) or len(rows) > TRIGGER_FIRST_PAIR_LIMIT
            or not isinstance(marked, tuple) or len(marked) > 8192
            or any(type(index) is not int or not 0 <= index < 8192 for index in marked)
            or len(set(marked)) != len(marked)):
        raise ValueError('trigger first hypothetical rows/marks exceed their profile')
    previous = -1
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'condition_position', 'script_index', 'declared_sense', 'captured_header_dependency_match'}
                or type(row['condition_position']) is not int or not previous < row['condition_position'] < 65536
                or type(row['script_index']) is not int or not 0 <= row['script_index'] < 8192
                or type(row['declared_sense']) is not int or not 0 <= row['declared_sense'] <= 2**32 - 1
                or (row['declared_sense'] & sum(phases)) not in phases
                or type(row['captured_header_dependency_match']) is not bool):
            raise ValueError('trigger first hypothetical condition is unsupported or unordered')
        previous = row['condition_position']
    # Pinned handleOneTrigger breaks after the first phase/name/Header match,
    # including when that first script slot is already marked. Never fall back.
    first = next((row for row in rows if row['declared_sense'] & phase
                  and row['captured_header_dependency_match']), None)
    return {'condition_position': first['condition_position'] if first else None,
        'script_index': first['script_index'] if first else None,
        'would_enter_unmarked_slot_branch': bool(first and first['script_index'] not in marked),
        'pair_scan_stops_at_first_match': first is not None}


def trigger_first_observe(proof, native_factory=header_match_native, comparator_factory=None):
    # Fresh complete raw admission/query chain; old first/match receipts cannot
    # replace the current capture. Temporal database events are still unknown.
    proof = header_match_observe(proof, native_factory, comparator_factory)
    matched = proof['header_match_observation']
    pairs = matched['pairs']
    if len(pairs) * 8 > TRIGGER_FIRST_ROW_WORK:
        raise ValueError('trigger first hypothetical row work exceeds its bound')
    groups = {}
    fields = ('condition_position', 'script_index', 'declared_sense', 'captured_header_dependency_match')
    for row in pairs:
        target, source = row['condition_owner'], row['source_owner']
        key = (trigger_source_key(target), trigger_source_key(source))
        if row['declared_provides_agree'] is not True:
            raise ValueError('trigger first requires the current agreed Header query')
        if key not in groups:
            if len(groups) >= TRIGGER_FIRST_PAIR_LIMIT:
                raise ValueError('trigger first Header pairs exceed their bound')
            groups[key] = {'condition_owner': target, 'source_owner': source, 'rows': []}
        group = groups[key]
        if group['condition_owner'] != target or group['source_owner'] != source:
            raise ValueError('trigger first Header pair identity changes')
        group['rows'].append({field: row[field] for field in fields})
    if len(groups) * len(TRIGGER_SOURCE_PHASES) > TRIGGER_FIRST_PHASE_LIMIT:
        raise ValueError('trigger first hypothetical phase cases exceed their bound')
    records = []
    for group in groups.values():
        phases = []
        for mask, name in TRIGGER_SOURCE_PHASES:
            unmarked = trigger_first_case(group['rows'], mask)
            marked = (trigger_first_case(group['rows'], mask, (unmarked['script_index'],))
                      if unmarked['script_index'] is not None else None)
            phases.append({'phase_mask': mask, 'phase': name,
                'if_no_slots_marked': unmarked, 'if_first_matching_slot_marked': marked})
        records.append({'condition_owner': group['condition_owner'], 'source_owner': group['source_owner'],
            'name_candidate_condition_positions': [row['condition_position'] for row in group['rows']],
            'hypothetical_phases': phases})
    encoded = json.dumps(records, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['trigger_first_observation'] = {'schema': 1, 'pairs': records, 'header_name_candidate_pairs': len(groups),
        'hypothetical_phase_cases': len(groups) * len(TRIGGER_SOURCE_PHASES),
        'hypothetical_pair_first_observed': bool(groups), 'conditional_row_work_bound': len(pairs) * 8,
        'pairs_bytes': len(encoded), 'pairs_sha256': hashlib.sha256(encoded).hexdigest(),
        'header_matches_sha256': matched['pairs_sha256'], 'source_conditions_sha256': matched['source_conditions_sha256'],
        'baseline_sha256': matched['baseline_sha256'], 'inventory_sha256': matched['inventory_sha256'],
        'scope': 'conditional pair-first/slot forecast over current captured Header results ONLY; ALL sources/phases/slot states UNSELECTED',
        **{flag: False for flag in ('headers_authenticated', 'native_library_identity_authenticated',
            'database_temporal_state_observed', 'transaction_temporal_sources_selected', 'trigger_phase_selected',
            'script_slot_state_observed', 'runtime_pair_first_selection_observed', 'provider_architectures_selected',
            'trigger_eligibility_complete', 'trigger_selection_complete', 'execution_order_complete',
            'script_execution_plan_complete', 'script_policy_satisfied', 'removal_policy_satisfied',
            'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

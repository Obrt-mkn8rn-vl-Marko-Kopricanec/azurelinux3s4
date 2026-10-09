"""Conditional countCorrection arithmetic, never runtime script arguments."""
import hashlib
import json

TRIGGER_ARGUMENT_CASES = 65536
TRIGGER_ARGUMENT_BYTES = 8 * 1024 * 1024
TRIGGER_ARGUMENT_AUTHORITIES = (*TRIGGER_COUNT_AUTHORITIES, 'count_correction_selected',
    'iterator_cardinality_observed', 'runtime_script_arguments_observed',
    'runtime_pair_first_selection_observed')


def trigger_argument_case(first, target_count, source_count, correction, route):
    if (type(target_count) is not int or not 0 <= target_count <= 32768
            or type(source_count) is not int or not 0 <= source_count <= 32768
            or type(correction) is not int or correction not in (-1, 0)
            or route not in ('database', 'immediate')):
        raise ValueError('trigger argument hypothetical counts/correction/route are unsupported')
    fields = {'condition_position', 'script_index', 'would_enter_unmarked_slot_branch',
              'pair_scan_stops_at_first_match'}
    if (not isinstance(first, dict) or set(first) != fields
            or type(first['would_enter_unmarked_slot_branch']) is not bool
            or type(first['pair_scan_stops_at_first_match']) is not bool):
        raise ValueError('trigger argument hypothetical first-slot case is malformed')
    match = first['condition_position'] is not None
    if match:
        if (type(first['condition_position']) is not int or not 0 <= first['condition_position'] < 65536
                or type(first['script_index']) is not int or not 0 <= first['script_index'] < 8192
                or first['pair_scan_stops_at_first_match'] is not True
                or (route == 'database' and not first['would_enter_unmarked_slot_branch'])):
            raise ValueError('trigger argument hypothetical first-slot case is inconsistent')
    elif (first['script_index'] is not None or first['would_enter_unmarked_slot_branch']
          or first['pair_scan_stops_at_first_match']):
        raise ValueError('trigger argument hypothetical first-slot absence is inconsistent')
    # runTriggers corrects the SOURCE count before entering its DB traversal;
    # handleOneTrigger receives correction=0 for the TARGET in that route.
    source_gate = source_count + correction >= 0 if route == 'database' else None
    query_target = bool(match and first['would_enter_unmarked_slot_branch']
                        and (source_gate is not False))
    arg1 = (target_count + (correction if route == 'immediate' else 0)
            if query_target else None)
    arg2 = source_count + correction if query_target and route == 'database' else None
    # runImmedTriggers passes rpmdbGetIteratorCount(mi), NOT a NAME-index
    # count. This observer has not acquired that temporal iterator receipt.
    return {'route': route, 'hypothetical_count_correction': correction,
        'condition_position': first['condition_position'], 'script_index': first['script_index'],
        'would_pass_source_count_gate': source_gate, 'would_query_target_count': query_target,
        'would_reach_script_call': query_target, 'conditional_arg1': arg1, 'conditional_arg2': arg2,
        'fresh_iterator_count_required': bool(query_target and route == 'immediate')}


def trigger_argument_observe(proof, comparator_factory=None):
    # Rebuild current raw counts and every accepted Header/first-slot guard.
    # Captured counts are held fixed only as explicit hypothetical operands.
    proof = trigger_count_observe(proof, comparator_factory=comparator_factory)
    firsts, counts = proof['trigger_first_observation'], proof['trigger_count_observation']
    pairs = firsts['pairs']
    if len(pairs) * len(TRIGGER_SOURCE_PHASES) * 6 > TRIGGER_ARGUMENT_CASES:
        raise ValueError('trigger argument hypothetical cases exceed their bound')
    by_name = {row['name']: row for row in counts['rows']}
    records, cases = [], 0
    for pair in pairs:
        target, source = pair['condition_owner'], pair['source_owner']
        target_row, source_row = by_name[target['name']], by_name[source['name']]
        phases = []
        for phase in pair['hypothetical_phases']:
            corrections = []
            for correction in (-1, 0):
                unmarked, marked = phase['if_no_slots_marked'], phase['if_first_matching_slot_marked']
                corrections.append({'count_correction': correction,
                    'database_if_unmarked': trigger_argument_case(unmarked,
                        target_row['native_after'], source_row['native_after'], correction, 'database'),
                    'immediate_if_unmarked': trigger_argument_case(unmarked,
                        target_row['native_after'], source_row['native_after'], correction, 'immediate'),
                    'immediate_if_first_marked': trigger_argument_case(marked,
                        target_row['native_after'], source_row['native_after'], correction, 'immediate')
                        if marked is not None else None})
                cases += 2 + (marked is not None)
            phases.append({'phase': phase['phase'], 'phase_mask': phase['phase_mask'],
                           'hypothetical_corrections': corrections})
        records.append({'condition_owner': target, 'source_owner': source,
            'target_current_count_row': target_row, 'source_current_count_row': source_row,
            'hypothetical_phases': phases})
    encoded = json.dumps(records, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > TRIGGER_ARGUMENT_BYTES:
        raise ValueError('trigger argument hypothetical output exceeds its serialization bound')
    proof['trigger_argument_observation'] = {'schema': 1, 'pairs': records,
        'header_name_candidate_pairs': len(pairs), 'hypothetical_argument_cases': cases,
        'conditional_arguments_forecast': bool(pairs),
        'pairs_bytes': len(encoded), 'pairs_sha256': hashlib.sha256(encoded).hexdigest(),
        'first_pairs_sha256': firsts['pairs_sha256'], 'count_rows_sha256': counts['rows_sha256'],
        'baseline_sha256': counts['baseline_sha256'], 'inventory_sha256': counts['inventory_sha256'],
        'scope': 'Conditional PSM arithmetic with CURRENT counts held fixed HYPOTHETICALLY; ALL routes/corrections/events/slots UNSELECTED. Immediate arg2 remains UNKNOWN without a fresh temporal iterator-count receipt.',
        **{flag: False for flag in TRIGGER_ARGUMENT_AUTHORITIES}}
    return proof

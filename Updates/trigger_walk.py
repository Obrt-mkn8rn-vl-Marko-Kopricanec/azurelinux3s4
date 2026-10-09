"""Conditional immediate-trigger walks with the CURRENT snapshot held fixed."""
import hashlib
import json
import re

trigger_walk_projection = False
TRIGGER_WALK_NAMES = 65536
TRIGGER_WALK_WORK = 131072
TRIGGER_WALK_CASES = 65536
TRIGGER_WALK_BYTES = 8 * 1024 * 1024
TRIGGER_WALK_AUTHORITIES = (*TRIGGER_ITERATOR_AUTHORITIES,
    'runtime_slot_transitions_observed', 'runtime_immediate_arguments_observed',
    'script_bodies_admitted', 'script_call_attempted')


def trigger_walk_lookup_plan(owners, known_rows):
    # Native delivery uses the SAME audit_header projections. The parent calls
    # this again only after rebuilding the complete accepted raw guard chain.
    names, conditions = set(), 0
    if not isinstance(owners, list) or len(owners) > 32768 + 128:
        raise ValueError('trigger walk owners exceed their lookup profile')
    for owner in owners:
        tags = {entry['tag']: entry for entry in owner['tags']}
        if len(tags) != len(owner['tags']):
            raise ValueError('trigger walk lookup tags are duplicated')
        projected = trigger_condition_values(owner, tags)
        for raw in projected.get(1066, ()):
            name = raw.decode('ascii')
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', name):
                raise ValueError('trigger walk lookup name is outside the declared profile')
            conditions += 1; names.add(name)
            if conditions > TRIGGER_WALK_NAMES:
                raise ValueError('trigger walk condition-name work exceeds its bound')
    known = {row['name'] for row in known_rows}
    # A name outside the complete installed/incoming name set has zero CURRENT
    # installed instances. Still observe its actual lookup; do not invent NULL.
    rows = [{'name': name, 'installed_instances': [], 'incoming_files': [],
             'inventory_count': 0} for name in sorted(names - known)]
    if len(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode('ascii')) > TRIGGER_WALK_BYTES:
        raise ValueError('trigger walk lookup plan exceeds its serialization bound')
    return rows


def trigger_walk_lookup_receipt(inventory, rows, before, after):
    # Reuse the exact typed sample discipline for a query subset with no
    # installed members, without describing it as a complete inventory scan.
    subset = {'headers': 0, 'baseline_sha256': inventory['baseline_sha256'],
              'entries_sha256': inventory['entries_sha256']}
    receipt = trigger_iterator_receipt(subset, rows, before, after)
    receipt.update(scope='CURRENT absent ordinary-condition NAME lookups bracketing TEST; not future PSM cardinality',
                   condition_name_lookups_observed=bool(rows),
                   count_and_complete_traversal_correspondence_observed=bool(rows))
    if not rows:
        receipt.update(samples=0, null_controls=0, new_rpm_api_calls=0)
    return receipt


def trigger_walk_work(conditions, lookups):
    counts = {}
    for row in conditions: counts[row['name']] = counts.get(row['name'], 0) + 1
    # Admission assumes every outer condition causes a full same-name source
    # scan. No early match/marked-slot shortcut is used to admit a larger case.
    return len(conditions) + sum(count * count * lookups[name]['count']
                                 for name, count in counts.items())


def trigger_walk_case(conditions, sources, lookups, phase, correction, target_count):
    if (type(phase) is not int or phase not in dict(TRIGGER_SOURCE_PHASES)
            or type(correction) is not int or correction not in (-1, 0)
            or type(target_count) is not int or not 0 <= target_count <= 32768
            or not isinstance(conditions, list) or len(conditions) > 4096
            or not isinstance(sources, list) or len(sources) > 32768
            or not isinstance(lookups, dict)):
        raise ValueError('trigger walk hypothetical inputs exceed their profile')
    names, by_name = set(), {}
    for position, row in enumerate(conditions):
        if (not isinstance(row, dict) or set(row) != {'condition_position', 'script_index', 'name', 'declared_sense'}
                or type(row['condition_position']) is not int or row['condition_position'] != position
                or type(row['script_index']) is not int or not 0 <= row['script_index'] < 8192
                or not isinstance(row['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', row['name'])
                or type(row['declared_sense']) is not int or not 0 <= row['declared_sense'] <= 2**32 - 1
                or row['declared_sense'] & sum(TRIGGER_PHASES) not in dict(TRIGGER_SOURCE_PHASES)):
            raise ValueError('trigger walk complete condition row is unsupported')
        names.add(row['name']); by_name.setdefault(row['name'], []).append(row)
    if set(lookups) != names:
        raise ValueError('trigger walk is missing complete current name lookups')
    instances = set()
    for name, row in lookups.items():
        if (not isinstance(row, dict) or set(row) != {'count', 'order'}
                or type(row['count']) is not int or not 0 <= row['count'] <= 32768
                or not isinstance(row['order'], list) or len(row['order']) != row['count']
                or any(type(value) is not int or not 1 <= value <= 2**32 - 1 for value in row['order'])
                or len(set(row['order'])) != len(row['order']) or instances.intersection(row['order'])):
            raise ValueError('trigger walk current lookup order/count is malformed')
        instances.update(row['order'])
    if trigger_walk_work(conditions, lookups) > TRIGGER_WALK_WORK:
        raise ValueError('trigger walk repeated-row work exceeds its bound')
    by_instance = {}
    fields = ('condition_position', 'script_index', 'declared_sense')
    for source in sources:
        if not isinstance(source, dict) or set(source) != {'owner', 'rows'}:
            raise ValueError('trigger walk source is malformed')
        owner, rows = source['owner'], source['rows']
        if (not isinstance(owner, dict) or owner.get('kind') != 'installed'
                or type(owner.get('instance')) is not int or owner['instance'] not in instances
                or owner['instance'] in by_instance or owner.get('name') not in names
                or owner['instance'] not in lookups[owner['name']]['order']
                or not isinstance(rows, list) or len(rows) != len(by_name[owner['name']])):
            raise ValueError('trigger walk source differs from the current lookup membership')
        for row, condition in zip(rows, by_name[owner['name']]):
            if (not isinstance(row, dict) or set(row) != {*fields, 'captured_header_dependency_match'}
                    or any(type(row[key]) is not int or row[key] != condition[key] for key in fields)
                    or type(row['captured_header_dependency_match']) is not bool):
                raise ValueError('trigger walk full source-query rows differ from the declarations')
        by_instance[owner['instance']] = source
    if set(by_instance) != instances:
        raise ValueError('trigger walk source-query membership is incomplete')
    # All conditions, lookup orders and query rows have been admitted BEFORE
    # searching. These marks are a conditional software state, not runtime data.
    marked, trace, calls = set(), [], []
    for condition in conditions:
        skip = condition['script_index'] in marked
        lookup = lookups[condition['name']]
        record = {'lookup_condition_position': condition['condition_position'], 'name': condition['name'],
                  'skipped_already_marked': skip, 'conditional_iterator_arg2': None if skip else lookup['count'],
                  'source_visits': []}
        if not skip:
            # The pinned outer loop does NOT filter by phase. handleOneTrigger
            # checks the whole same-name array and breaks at its first match,
            # even when that first slot is already marked.
            for instance in lookup['order']:
                source = by_instance[instance]
                first = trigger_first_case(source['rows'], phase, tuple(sorted(marked)))
                attempt = first['would_enter_unmarked_slot_branch']
                visit = {'source_owner': source['owner'], **first,
                         'conditional_arg1': target_count + correction if attempt else None,
                         'conditional_arg2': lookup['count'] if attempt else None}
                record['source_visits'].append(visit)
                if attempt:
                    calls.append({'lookup_condition_position': condition['condition_position'], **visit})
                    # Pinned code marks after the call attempt regardless of its
                    # return code. No script/body/outcome is evaluated here.
                    marked.add(first['script_index'])
        trace.append(record)
    return {'lookups': trace, 'conditional_call_attempts': calls, 'final_marked_slots': sorted(marked)}


def trigger_walk_observe(proof, comparator_factory=None):
    proof = trigger_iterator_observe(proof, comparator_factory=comparator_factory)
    inventory = proof['effects']['installed_versions']
    current = proof['trigger_iterator_observation']
    owners = [*proof['effects']['installed_script_owners'], *proof['effects']['incoming']]
    extra_rows = trigger_walk_lookup_plan(owners, current['rows'])
    raw = proof['effects']['ordinary_condition_name_lookups']
    if not isinstance(raw, dict) or not isinstance(raw.get('rows'), list) or len(raw['rows']) != len(extra_rows):
        raise ValueError('trigger walk raw extra lookup receipt is missing')
    extra = trigger_walk_lookup_receipt(inventory, extra_rows,
        [row['before'] for row in raw['rows']], [row['after'] for row in raw['rows']])
    if not trigger_iterator_equal(raw, extra):
        raise ValueError('trigger walk raw extra lookups differ from current declarations')
    native_rows = {row['name']: row for row in [*current['rows'], *extra['rows']]}
    count_rows = {row['name']: row for row in proof['trigger_count_observation']['rows']}
    targets, installed, queries = {}, {}, {}
    for declaration in proof['provides_observation']['owners']:
        owner = {key: value for key, value in declaration.items() if key not in ('source_tags', 'provides')}
        if owner['kind'] == 'installed': installed[owner['instance']] = owner
    for row in proof['trigger_source_observation']['conditions']:
        key = trigger_source_key(row['owner'])
        target = targets.setdefault(key, {'owner': row['owner'], 'conditions': []})
        target['conditions'].append({field: row[field] for field in
            ('condition_position', 'script_index', 'name', 'declared_sense')})
    for row in proof['header_match_observation']['pairs']:
        if row['source_owner']['kind'] != 'installed': continue
        key = (trigger_source_key(row['condition_owner']), row['source_owner']['instance'])
        queries.setdefault(key, []).append({field: row[field] for field in
            ('condition_position', 'script_index', 'declared_sense', 'captured_header_dependency_match')})
    if len(targets) * 16 > TRIGGER_WALK_CASES:
        raise ValueError('trigger walk scenario count exceeds its bound')
    plans, work = [], 0
    for key, target in targets.items():
        conditions = target['conditions']; names = {row['name'] for row in conditions}
        lookups = {name: {'count': native_rows[name]['before']['count_start'],
                         'order': native_rows[name]['before']['order']} for name in names}
        work += 16 * trigger_walk_work(conditions, lookups)
        if work > TRIGGER_WALK_WORK:
            raise ValueError('trigger walk complete repeated-row work exceeds its bound')
        sources = [{'owner': installed[instance], 'rows': queries[(key, instance)]}
                   for instance in sorted({value for lookup in lookups.values() for value in lookup['order']})]
        plans.append((target, sources, names))
    observations = []
    for target, sources, names in plans:
        scenarios = []
        for sample in ('before', 'after'):
            lookups = {name: {'count': native_rows[name][sample]['count_start'],
                             'order': native_rows[name][sample]['order']} for name in names}
            target_count = count_rows[target['owner']['name']]['native_' + sample]
            for mask, phase in TRIGGER_SOURCE_PHASES:
                for correction in (-1, 0):
                    scenarios.append({'sample': sample, 'phase': phase, 'phase_mask': mask,
                        'hypothetical_count_correction': correction, 'current_target_count': target_count,
                        **trigger_walk_case(target['conditions'], sources, lookups, mask, correction, target_count)})
        observations.append({**target, 'hypothetical_scenarios': scenarios})
    encoded = json.dumps(observations, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > TRIGGER_WALK_BYTES:
        raise ValueError('trigger walk complete output exceeds its serialization bound')
    proof['trigger_walk_observation'] = {'schema': 1, 'targets': observations,
        'conditional_walk_forecast_constructed': bool(targets), 'target_headers': len(targets),
        'hypothetical_scenarios': len(targets) * 16, 'admitted_repeated_row_work': work,
        'targets_bytes': len(encoded), 'targets_sha256': hashlib.sha256(encoded).hexdigest(),
        'extra_current_name_lookups': extra, 'current_iterators_sha256': current['rows_sha256'],
        'header_queries_sha256': proof['header_match_observation']['pairs_sha256'],
        'source_conditions_sha256': proof['trigger_source_observation']['conditions_sha256'],
        'baseline_sha256': inventory['baseline_sha256'], 'inventory_sha256': inventory['entries_sha256'],
        'scope': 'Conditional immediate-trigger walk with CURRENT membership, query booleans and each sampled order held FIXED. All targets/phases/corrections/calls UNSELECTED; future temporal arg2 remains UNKNOWN.',
        **{flag: False for flag in TRIGGER_WALK_AUTHORITIES}}
    return proof

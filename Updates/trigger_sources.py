"""Join ordinary trigger declarations to source package names and possible phases."""

import hashlib
import json


TRIGGER_SOURCE_PAIR_LIMIT = 16384
TRIGGER_SOURCE_PHASES = ((1 << 16, 'in'), (1 << 17, 'un'),
                         (1 << 18, 'postun'), (1 << 25, 'prein'))


def trigger_source_key(owner):
    return (owner['kind'], owner['instance'] if owner['kind'] == 'installed' else owner['file'])


def trigger_source_observe(proof, comparator_factory=provider_native):
    # Rebuild current raw declarations and native comparisons, never reuse a
    # receipt. Possible phase predicates below do NOT select a temporal event.
    proof = provider_observe(proof, comparator_factory)
    declaration = proof['provides_observation']
    conditions = proof['provider_match_observation']['conditions']
    by_name, by_key, sources = {}, {}, []
    removed = {owner['instance'] for owner in proof['effects']['removals']}
    for owner in declaration['owners']:
        identity = {key: value for key, value in owner.items() if key not in ('source_tags', 'provides')}
        key = trigger_source_key(identity)
        if key in by_key:
            raise ValueError('trigger source header identity is repeated')
        by_key[key] = identity
        source = {'owner': identity, 'observed_removal': identity['kind'] == 'installed' and identity['instance'] in removed}
        sources.append(source); by_name.setdefault(identity['name'], []).append(source)
    pairs = sum(len(by_name.get(condition['name'], ())) for condition in conditions)
    if pairs > TRIGGER_SOURCE_PAIR_LIMIT:
        raise ValueError('trigger source package-name pairs exceed their bound')
    records, compared = [], 0
    for condition in conditions:
        phase = condition['declared_sense'] & sum(TRIGGER_PHASES)
        if phase not in dict(TRIGGER_SOURCE_PHASES):
            raise ValueError('trigger source declared phase is unsupported')
        dependency_by_source, other = {}, []
        for row in condition['sources_compared']:
            identity = row['source']['owner']; key = trigger_source_key(identity)
            if identity != by_key.get(key) or type(row['declared_dependency_overlap']) is not bool:
                raise ValueError('trigger source comparison differs from its current header')
            result = {'provide_position': row['source']['position'],
                      'declared_dependency_overlap': row['declared_dependency_overlap']}
            if identity['name'] == condition['name']:
                dependency_by_source.setdefault(key, []).append(result)
            else:
                other.append({'owner': identity, **result, 'source_package_name_equal': False})
        candidates = []
        for source in by_name.get(condition['name'], ()):
            compared += 1
            if compared > TRIGGER_SOURCE_PAIR_LIMIT:
                raise ValueError('trigger source package-name work exceeds its bound')
            dependencies = dependency_by_source.get(trigger_source_key(source['owner']), [])
            overlap = any(row['declared_dependency_overlap'] for row in dependencies)
            candidates.append({**source, 'source_package_name_equal': True,
                'declared_provides_compared': dependencies,
                'same_name_declared_provides_overlap': overlap,
                'possible_phase_predicates': [{'phase_mask': mask, 'phase': name,
                    'declared_phase_equal': phase == mask,
                    'name_and_declared_provides_and_phase_overlap': overlap and phase == mask}
                    for mask, name in TRIGGER_SOURCE_PHASES]})
        records.append({key: condition[key] for key in
            ('owner', 'condition_position', 'script_index', 'name', 'evr', 'declared_sense')}
            | {'declared_phase_mask': phase, 'declared_phase': dict(TRIGGER_SOURCE_PHASES)[phase],
               'package_name_sources': candidates, 'different_package_providers': other})
    material = json.dumps(records, sort_keys=True, separators=(',', ':')).encode('ascii')
    source_material = json.dumps(sources, sort_keys=True, separators=(',', ':')).encode('ascii')
    proof['trigger_source_observation'] = {'schema': 1, 'conditions': records,
        'ordinary_conditions': len(records), 'source_headers': len(sources), 'package_name_pairs': compared,
        'source_package_names_compared': bool(compared), 'declared_phase_relationships_observed': bool(records),
        'conditions_bytes': len(material), 'conditions_sha256': hashlib.sha256(material).hexdigest(),
        'sources_bytes': len(source_material), 'sources_sha256': hashlib.sha256(source_material).hexdigest(),
        'provider_comparisons_sha256': proof['provider_match_observation']['conditions_sha256'],
        'provides_sha256': declaration['owners_sha256'],
        'declaration_sha256': proof['trigger_condition_observation']['owners_sha256'],
        'baseline_sha256': proof['baseline']['sha256'], 'inventory_sha256': declaration['inventory_sha256'],
        'scope': 'source package-name equality and hypothetical phase predicates over declared Provides ONLY; ALL headers/events remain UNSELECTED',
        **{flag: False for flag in ('actual_header_dependency_matches_observed', 'trigger_phase_selected',
            'transaction_temporal_sources_selected', 'provider_architectures_selected', 'trigger_eligibility_complete',
            'trigger_selection_complete', 'execution_order_complete', 'script_execution_plan_complete',
            'installed_headers_authenticated', 'native_library_identity_authenticated', 'script_policy_satisfied',
            'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized', 'scripts_executed', 'server_ready')}}
    return proof

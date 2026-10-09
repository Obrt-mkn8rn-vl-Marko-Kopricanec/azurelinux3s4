"""Declared PSM caller routes, not selected temporal processing or scripts."""
import hashlib
import json

PSM_ROUTE_HEADER_BYTES = 8 * 1024 * 1024
PSM_ROUTE_CASES = 65536
PSM_ROUTE_BYTES = 8 * 1024 * 1024
PSM_ROUTE_AUTHORITIES = (*PSM_INPUT_AUTHORITIES,
    'caller_goal_type_selected', 'transaction_phase_selected',
    'transscript_presence_read_back', 'package_header_opened_for_processing',
    'temporal_processing_state_observed')


def psm_route_case(kind, pre_body, pre_program, post_body, post_program):
    if (type(kind) is not str or kind not in ('incoming', 'removed')
            or any(type(value) is not bool for value in (pre_body, pre_program, post_body, post_program))):
        raise ValueError('PSM route caller operands are unsupported')
    routes = [{'caller': 'rpmtsProcess', 'goal': 'PKG_INSTALL' if kind == 'incoming' else 'PKG_ERASE',
               'caller_kind_matches': True, 'declared_transscript_present': None,
               'conditional_open_attempt': True}]
    for goal, body, program in (('PKG_PRETRANS', pre_body, pre_program),
                                ('PKG_POSTTRANS', post_body, post_program)):
        # runTransScripts uses TR_ADDED for these two goals. Presence is an
        # OR of Header tag declarations, not body execution or loadability.
        routes.append({'caller': 'runTransScripts', 'goal': goal,
            'caller_kind_matches': kind == 'incoming', 'declared_body_present': body,
            'declared_program_present': program, 'declared_transscript_present': body or program,
            'conditional_open_attempt': kind == 'incoming' and (body or program)})
    return routes


def psm_route_headers(proof, inventory, plan):
    audit = proof['effects']
    captured, incoming = audit['installed_header_exports'], audit['incoming']
    if (not isinstance(captured, list) or len(captured) != len(inventory['entries'])
            or not isinstance(incoming, list) or len(incoming) != len(plan['incoming'])):
        raise ValueError('PSM route complete captured Header inventory is missing')
    sources, total, seen = [], 0, set()
    for expected, value in zip(inventory['entries'], captured):
        if (not isinstance(value, dict) or set(value) != {*INSTALLED_VERSION_FIELDS, 'header_export_hex'}
                or not trigger_iterator_equal({key: value[key] for key in INSTALLED_VERSION_FIELDS}, expected)):
            raise ValueError('PSM route installed Header identity/order differs')
        sources.append(('installed', value['instance'], expected, value))
    for value in incoming:
        if not isinstance(value, dict): raise ValueError('PSM route incoming Header is unsupported')
        key = value['file']; expected = plan['incoming'].get(key)
        if (key in seen or expected is None
                or not trigger_iterator_equal({field: value[field] for field in expected if field != 'kind'},
                                              {field: item for field, item in expected.items() if field != 'kind'})):
            raise ValueError('PSM route incoming Header identity differs')
        seen.add(key); sources.append(('incoming', key, expected, value))
    for _, _, _, value in sources:
        trigger_number(value['header_bytes'], 8, HEADER_INPUT_BYTES)
        total += value['header_bytes']
    if total > PSM_ROUTE_HEADER_BYTES:
        raise ValueError('PSM route complete Header bytes exceed their bound')
    installed = {value['instance']: value for value in inventory['entries']}
    metadata = {}
    for value in audit['installed_script_owners']:
        instance = value['instance']
        if (type(instance) is not int or instance not in installed or instance in metadata
                or not trigger_iterator_equal({field: value[field] for field in INSTALLED_VERSION_FIELDS}, installed[instance])):
            raise ValueError('PSM route installed metadata identity differs')
        metadata[instance] = value
    if len(metadata) != len(audit['installed_script_owners']):
        raise ValueError('PSM route installed metadata is duplicated')
    declarations, records, observed_metadata = {}, [], set()
    for source, key, owner, value in sources:
        material = header_input_material(value); audited = audit_header(material)
        tags = trigger_tags(audited)
        if source == 'incoming':
            if not trigger_iterator_equal(audited['tags'], value['tags']):
                raise ValueError('PSM route incoming tags differ from the SAME export')
        elif audited['tags']:
            if key not in metadata or not trigger_iterator_equal(audited['tags'], metadata[key]['tags']):
                raise ValueError('PSM route installed tags differ from the SAME export')
            observed_metadata.add(key)
        elif key in metadata:
            raise ValueError('PSM route scriptless export differs from installed metadata')
        selected = [tags[tag] for tag in (1151, 1153, 1152, 1154) if tag in tags]
        declarations[(source, key)] = set(tags)
        records.append({'source': source, 'owner': owner, 'transscript_tags': selected})
    if observed_metadata != set(metadata):
        raise ValueError('PSM route complete installed metadata membership differs')
    return declarations, records, total


def psm_route_forecast(proof):
    source = proof['effects']['installed_versions']
    inventory, plan = transaction_element_plan({row['instance']: row for row in source['entries']},
        proof['baseline'], proof['effects']['incoming'], proof['effects']['removals'])
    elements, inputs = proof['effects']['ordered_transaction_elements'], proof['effects']['current_psm_inputs']
    rebuilt = psm_input_receipt(inventory, plan, elements, inputs['before'], inputs['after'])
    if not trigger_iterator_equal(inputs, rebuilt) or any(row['is_source'] for row in rebuilt['before']):
        raise ValueError('PSM route requires the complete CURRENT binary-source receipt')
    case_count = 6 * len(elements['before'])
    if case_count > PSM_ROUTE_CASES: raise ValueError('PSM route caller cases exceed their bound')
    declarations, headers, header_bytes = psm_route_headers(proof, inventory, plan)
    rows, encoded, size = [], [], 2
    for sample in ('before', 'after'):
        for element in elements[sample]:
            owner = element['owner']; key = ('incoming', owner['file']) if owner['kind'] == 'incoming' else ('installed', owner['instance'])
            tags = declarations[key]
            row = {'sample': sample, 'element': element,
                'conditional_caller_routes': psm_route_case(owner['kind'], 1151 in tags, 1153 in tags, 1152 in tags, 1154 in tags)}
            data = json.dumps(row, sort_keys=True, separators=(',', ':')).encode('ascii')
            size += len(data) + bool(rows)
            if size > PSM_ROUTE_BYTES: raise ValueError('PSM route matrix exceeds its serialization bound')
            rows.append(row); encoded.append(data)
    material = b'[' + b','.join(encoded) + b']'
    if len(material) != size: raise ValueError('PSM route matrix serialization differs')
    headers_encoded = json.dumps(headers, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(headers_encoded) > PSM_ROUTE_BYTES: raise ValueError('PSM route Header declarations exceed their serialization bound')
    return {'schema': 1, 'rows': rows, 'rows_bytes': size, 'rows_sha256': hashlib.sha256(material).hexdigest(),
        'headers': headers, 'headers_bytes': len(headers_encoded), 'headers_sha256': hashlib.sha256(headers_encoded).hexdigest(),
        'header_exports_audited': len(headers), 'header_export_bytes': header_bytes,
        'conditional_caller_cases': case_count, 'conditional_routes_forecast': bool(rows), 'new_rpm_api_calls': 0,
        'inventory_sha256': inventory['entries_sha256'], 'baseline_sha256': inventory['baseline_sha256'],
        'fresh_runtime_kind_header_open_phase_and_flags_required': True,
        'scope': 'UNSELECTED rpmtsProcess install/erase and runTransScripts pre/posttrans SOURCE routes on CURRENT elements and SAME export tag presence ONLY; no temporal processing, flags, open success, scripts or eligibility',
        **{flag: False for flag in PSM_ROUTE_AUTHORITIES}}


def psm_route_observe(proof, comparator_factory=None):
    proof = psm_input_observe(proof, comparator_factory=comparator_factory)
    proof['psm_route_observation'] = psm_route_forecast(proof)
    return proof

"""Literal declared transaction paths versus observed interpreter lookup paths."""


INTERPRETER_PATH_LIMIT = 131072
INTERPRETER_MATCH_LIMIT = 65536


def interpreter_path_number(value, limit):
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError('interpreter path metadata integer is missing or excessive')
    return value


def interpreter_pathname(value):
    return value if value == '/' else pathname(value)


def interpreter_paths(proof):
    source, observed = proof['namespace_inventory'], proof['interpreters']
    if (not isinstance(source, dict) or type(source.get('schema')) is not int or source['schema'] != 1
            or not isinstance(source.get('incoming'), list) or len(source['incoming']) > 128
            or not isinstance(source.get('removals'), list) or len(source['removals']) > proof['baseline']['headers']
            or any(source.get(name) is not False for name in ('installed_headers_authenticated',
                'operation_selection_complete', 'snapshot_atomic', 'installation_authorized'))
            or observed.get('schema') != 1 or observed.get('external_files_observed') is not True
            or any(observed.get(name) is not False for name in ('runtime_files_authenticated', 'execution_tested',
                'execution_policy_satisfied', 'trigger_selection_complete', 'installation_authorized'))
            or not isinstance(observed.get('files'), list) or len(observed['files']) > 64):
        raise ValueError('interpreter path correspondence lacks qualified current observations')
    lookup, files = {}, set()
    for entry in observed['files']:
        command, resolved, paths = pathname(entry['path']), pathname(entry['resolved_path']), entry['lookup_paths']
        if (command in files or not isinstance(paths, list) or not 1 <= len(paths) <= 1026
                or paths != sorted(set(paths)) or command not in paths or resolved not in paths):
            raise ValueError('interpreter lookup inventory is missing or inconsistent')
        files.add(command)
        for path in paths:
            interpreter_pathname(path)
            lookup.setdefault(path, []).append((command, 'declared' if path == command else
                                               'resolved' if path == resolved else 'lookup-ancestor-or-link'))
    hits, total, incoming_files, removed_instances = [], 0, set(), set()
    for kind, records, owners in (('incoming', source['incoming'], proof['effects']['incoming']),
                                 ('removal', source['removals'], proof['effects']['removals'])):
        if len(records) != len(owners):
            raise ValueError('interpreter namespace owner inventory differs from the current TEST')
        fields = ('name', 'nevra', 'header_bytes', 'header_sha256') + (
            ('file', 'sha256', 'bytes') if kind == 'incoming' else ('instance',))
        for record, owner in zip(records, owners):
            if (not isinstance(record, dict) or set(record) != {*fields, 'files'}
                    or {name: record[name] for name in fields} != {name: owner[name] for name in fields}
                    or not isinstance(record['files'], list)):
                raise ValueError('interpreter namespace header/snapshot binding is inconsistent')
            key = record['file'] if kind == 'incoming' else record['instance']
            seen = incoming_files if kind == 'incoming' else removed_instances
            if key in seen:
                raise ValueError('interpreter namespace owner is repeated')
            seen.add(key)
            total += len(record['files'])
            if total > INTERPRETER_PATH_LIMIT:
                raise ValueError('interpreter declared path inventory exceeds its bound')
            names = set()
            binding = {name: record[name] for name in fields}
            for item in record['files']:
                if not isinstance(item, dict) or set(item) != {'path', 'bytes', 'mode', 'flags', 'link'}:
                    raise ValueError('interpreter declared path record is malformed')
                path = interpreter_pathname(item['path'])
                if path in names:
                    raise ValueError('interpreter declared path is repeated within a header')
                names.add(path)
                interpreter_path_number(item['bytes'], 16 * 1024**3)
                mode = interpreter_path_number(item['mode'], 65535)
                interpreter_path_number(item['flags'], 2**32 - 1)
                if (not isinstance(item['link'], str) or len(item['link'].encode('utf-8')) > 4096
                        or any(ord(value) < 32 or ord(value) == 127 for value in item['link'])
                        or stat.S_ISLNK(mode) and not item['link']
                        or not stat.S_ISLNK(mode) and item['link']):
                    raise ValueError('interpreter declared link metadata is unsupported')
                for command, relationship in lookup.get(path, []):
                    hits.append({'source': kind, 'owner': binding, 'declaration': item,
                                 'interpreter': command, 'relationship': relationship})
                    if len(hits) > INTERPRETER_MATCH_LIMIT:
                        raise ValueError('interpreter path correspondence exceeds its match bound')
    if interpreter_path_number(source['files'], INTERPRETER_PATH_LIMIT) != total:
        raise ValueError('interpreter declared file count differs from the complete inventory')
    material = json.dumps(source, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(material) > 32 * 1024 * 1024:
        raise ValueError('interpreter namespace inventory exceeds its byte bound')
    proof['interpreter_path_correspondence'] = {
        'schema': 1, 'matches': hits, 'declared_files': total, 'observed_interpreter_files': len(files),
        'inventory_sha256': hashlib.sha256(material).hexdigest(),
        'literal_path_correspondence_complete': True, 'potential_literal_path_changes': bool(hits),
        'scope': 'literal declared incoming/removal paths versus requested/resolved/observed lookup paths ONLY',
        **{name: False for name in ('installed_headers_authenticated', 'operation_selection_complete',
            'alternate_aliases_checked', 'hardlink_effects_checked', 'future_interpreter_bytes_authenticated',
            'transaction_order_complete', 'interpreter_transaction_continuity_proven', 'execution_policy_satisfied',
            'snapshot_atomic', 'installation_authorized', 'scripts_executed', 'server_ready')},
    }
    return proof

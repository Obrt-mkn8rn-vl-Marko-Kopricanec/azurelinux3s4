"""Bind original database declarations before inactive application storage only."""


DATABASE_CORRESPONDENCE_AUTHORITY = (
    'release_and_configuration_intent_authenticated', 'actual_npgsql_parsing_proven',
    'password_material_authenticated', 'database_roles_and_schema_provisioned',
    'loaded_hba_and_socket_context_proven', 'database_connections_usable',
    'dns_epoch_and_writer_lease_proven', 'gateway_restricted_role_probe_passed',
    'postgresql_version_and_provider_authenticated', 'application_ready',
)


def database_original(path, rows):
    selected = [row for row in rows if row.get('file', row.get('source')) == path]
    if len(selected) != 1:
        raise ValueError('one complete original database source commitment required')
    row = selected[0]
    data = deployment_read(path)
    if (type(row.get('bytes')) is not int or row['bytes'] != len(data)
            or row.get('sha256') != dep_hash.sha256(data).hexdigest()):
        raise ValueError('original database source byte correspondence')
    return data


def database_dns_declaration(data, profile):
    # An intentionally small unquoted Npgsql subset with explicit endpoint,
    # principal and password fields. No aliases, whitespace, terminal LF,
    # duplicate keys or optional overrides; other native/environment state is open.
    # The original consumer passes the complete UTF8 string without trimming.
    if (type(data) is not bytes or not 1 <= len(data) <= 4096
            or any(byte < 33 or byte > 126 for byte in data)):
        raise ValueError('bounded unquoted DNS database declaration required')
    fields = {}
    for part in data.decode('ascii').split(';'):
        key, separator, value = part.partition('=')
        if (not separator or key not in ('Host', 'Port', 'Database', 'Username', 'Password')
                or key in fields or not value):
            raise ValueError('exact unique DNS database parameters required')
        fields[key] = value
    if (set(fields) != {'Host', 'Port', 'Database', 'Username', 'Password'}
            or fields['Host'] != profile['dns_controller']['host_directory']
            or fields['Port'] != str(profile['required_observed_settings']['port'])
            or fields['Database'] != profile['dns_controller']['database']
            or fields['Username'] != profile['dns_controller']['login_role']
            or not dep_re.fullmatch(r'[A-Za-z0-9+/._~-]{16,128}', fields['Password'])):
        raise ValueError('DNS database declaration must match fixed PostgreSQL profile')
    # Password syntax is not entropy, authentication or usability evidence.
    return {'role': 'dns-controller', 'transport': 'Unix socket',
            'host': fields['Host'], 'port': int(fields['Port']),
            'database': fields['Database'], 'login_role': fields['Username']}


def application_database_observe(candidate):
    files, profile = postgresql_profile()
    originals, roles = {}, []
    # BOTH original Email declaration sets are fully admitted before nested reads.
    for role in ('worker', 'gateway'):
        path = '/etc/mk8.email/' + role + '.json'
        originals[path] = database_original(path, candidate['configuration'])
        declaration = email_transport_plan(originals[path])['database']
        host, port, name, user = declaration
        if (host not in ('127.0.0.1', '::1') or port != profile['required_observed_settings']['port']
                or name != profile['email']['database']
                or user != profile['email'][role + '_login_role']):
            raise ValueError('Email database declaration must match fixed PostgreSQL profile')
        roles.append({'role': 'email-' + role, 'transport': 'loopback TCP',
                      'host': host, 'port': port, 'database': name, 'login_role': user})
    # These are the sources already guarded by the complete fresh candidate.
    path = '/etc/mk8.dns/control-plane.json'
    originals[path] = database_original(path, candidate['configuration'])
    if release_json(originals[path]).get('ConnectionStringFile') != '/run/mk8.dns/controller/inputs/database.txt':
        raise ValueError('DNS original database credential reference required')
    dns = [row for row in candidate['dns_credentials'] if row['role'] == 'controller']
    email = candidate['email_credentials']
    if len(dns) != 1 or [row['role'] for row in email] != ['worker', 'gateway']:
        raise ValueError('complete original database credential plans required')
    path = '/etc/mk8.dns/controller/database.txt'
    originals[path] = database_original(path, dns[0]['inputs'])
    roles.insert(0, database_dns_declaration(originals[path], profile))
    for role, plan in zip(('worker', 'gateway'), email):
        path = '/etc/mk8.email/' + role + '/database-password.txt'
        originals[path] = database_original(path, plan['inputs'])
    # Sequential original-byte correspondence; no atomicity or ABA claim.
    for path, data in originals.items():
        if deployment_read(path) != data:
            raise ValueError('original database inputs changed after admission')
    return {'profile_files': [{key: row[key] for key in ('file', 'bytes', 'sha256')} for row in files],
            'minimum_server_version_num': profile['minimum_server_version_num'], 'roles': roles,
            'sources': [{'file': path, 'bytes': len(data), 'sha256': dep_hash.sha256(data).hexdigest()}
                        for path, data in sorted(originals.items())],
            'authority': {name: False for name in DATABASE_CORRESPONDENCE_AUTHORITY}}

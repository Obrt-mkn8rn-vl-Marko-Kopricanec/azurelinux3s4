"""Observe declared Email store endpoints and source-derived payload budgets only."""


EMAIL_TRANSPORT_AUTHORITY = (
    'complete_environment_schema_validated', 'actual_dotnet_deserialization_proven',
    'database_roles_and_schema_provisioned', 'database_connection_usable',
    'blob_connection_and_container_usable', 'secret_material_and_keys_validated',
    'listener_and_transport_enforcement_proven', 'current_pair_runtime_correspondence_proven',
    'application_ready',
)
EMAIL_TRANSPORT_FIELDS = {
    'Database': EMAIL_RECORD_FIELDS['Database'],
    'Messaging': EMAIL_RECORD_FIELDS['Messaging'],
    'ObjectStorage': EMAIL_RECORD_FIELDS['ObjectStorage'],
    'Limits': ('MaxMessageSizeBytes', 'MaxRecipientsPerMessage',
               'ConnectionTimeoutSeconds', 'MaxConnectionsPerIp'),
    'Jmap': ('Port', 'EnableJmap', 'IsDefault', 'PublicBaseUrl', 'MaxUploadSizeBytes',
             'MaxRequestSizeBytes', 'MaxCallsInRequest', 'MaxObjectsInGet', 'MaxObjectsInSet',
             'MaxConcurrentRequests', 'MaxConcurrentUploads', 'UploadRetentionHours',
             'MaxUnreferencedBlobBytesPerAccount'),
    'Dav': ('EnableDav', 'MaxResourceSizeBytes', 'MaxCollectionsPerUser', 'MaxResourcesPerCollection'),
}
EMAIL_TRANSPORT_BOUNDS = {
    'Messaging': {'MaxPayloadBytes': (67108864, 65536, 1073741824),
        'InlinePayloadThresholdBytes': (262144, 0, 1048576), 'LeaseSeconds': (120, 5, 3600),
        'NotificationFallbackSeconds': (30, 1, 300)},
    'Limits': {'MaxMessageSizeBytes': (10485760, 65536, 2147483647),
        'MaxRecipientsPerMessage': (100, 1, 1000), 'ConnectionTimeoutSeconds': (300, 10, 3600),
        'MaxConnectionsPerIp': (10, 1, 10000)},
    'Jmap': {'MaxUploadSizeBytes': (50000000, 1048576, 1073741824),
        'MaxRequestSizeBytes': (10000000, 65536, 104857600), 'MaxCallsInRequest': (64, 1, 1024),
        'MaxObjectsInGet': (500, 1, 10000), 'MaxObjectsInSet': (500, 1, 10000),
        'MaxConcurrentRequests': (8, 1, 1024), 'MaxConcurrentUploads': (4, 1, 128),
        'UploadRetentionHours': (24, 1, 168),
        'MaxUnreferencedBlobBytesPerAccount': (100000000, 1, 9007199254740991)},
    'Dav': {'MaxResourceSizeBytes': (10485760, 65536, 1073741824),
        'MaxCollectionsPerUser': (100, 1, 1000), 'MaxResourcesPerCollection': (100000, 1, 1000000)},
}


def email_transport_integer(value, key, default, minimum, maximum):
    number = value.get(key, default)
    if type(number) is not int or not minimum <= number <= maximum:
        raise ValueError('bounded Email transport integer declaration required')
    return number


def email_transport_boolean(value, key, default):
    flag = value.get(key, default)
    if type(flag) is not bool:
        raise ValueError('typed Email transport boolean declaration required')
    return flag


def email_transport_binary(size):
    return 4 * ((size + 2) // 3) + 262144


def email_transport_plan(data):
    value = email_record(release_json(data), EMAIL_ROOT_FIELDS)
    records = {name: email_record(value.get(name, {}), fields)
               for name, fields in EMAIL_TRANSPORT_FIELDS.items()}
    database, messaging, storage = (records[name] for name in ('Database', 'Messaging', 'ObjectStorage'))
    host = database.get('Host', 'localhost')
    if type(host) is not str or host not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('declared local Email PostgreSQL endpoint required')
    port = email_transport_integer(database, 'Port', 5432, 1, 65535)
    names = [database.get('Name', 'mk8email'), database.get('Username', 'postgres')]
    if any(type(name) is not str or not dep_re.fullmatch(r'[a-z][a-z0-9_]{0,62}', name) for name in names):
        raise ValueError('bounded canonical Email database identifiers required')
    if email_transport_boolean(messaging, 'Enabled', False) is not True:
        raise ValueError('declared enabled Email messaging required')
    worker = messaging.get('WorkerId')
    if worker is not None and (type(worker) is not str or
            not dep_re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}', worker)):
        raise ValueError('bounded Email messaging worker identifier required')
    provider = storage.get('Provider', 'azure-blob')
    container, prefix = storage.get('ContainerName', 'mk8-email-objects'), storage.get('ObjectPrefix', '')
    if (provider != 'azure-blob' or type(container) is not str or
            not dep_re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', container) or '--' in container):
        raise ValueError('canonical Email Blob provider and container required')
    # Conservative printable ASCII subset of the original prefix contract.
    if (type(prefix) is not str or len(prefix) > 512 or prefix.startswith('/') or '//' in prefix
            or any(not 33 <= ord(character) <= 126 for character in prefix)):
        raise ValueError('bounded canonical Email Blob prefix required')
    create = email_transport_boolean(storage, 'CreateContainerIfMissing', False)
    effective = {name: {key: email_transport_integer(records[name], key, *bounds)
                       for key, bounds in fields.items()}
                 for name, fields in EMAIL_TRANSPORT_BOUNDS.items()}
    jmap = email_transport_boolean(records['Jmap'], 'EnableJmap', True)
    dav = email_transport_boolean(records['Dav'], 'EnableDav', True)
    payload = effective['Messaging']['MaxPayloadBytes']
    message = effective['Limits']['MaxMessageSizeBytes']
    # Match BOTH original formulas; the older APPEND integer rounding differs
    # from the separate HTTP binary-envelope formula.
    required = max((4 * message + 2) // 3 + 1048576, email_transport_binary(65536))
    if jmap:
        upload, request = (effective['Jmap'][key] for key in ('MaxUploadSizeBytes', 'MaxRequestSizeBytes'))
        required = max(required, email_transport_binary(upload), 6 * request + 262144)
        if effective['Jmap']['MaxUnreferencedBlobBytesPerAccount'] < max(upload, message):
            raise ValueError('Email JMAP blob retention declaration below source bound')
    if dav:
        resource = effective['Dav']['MaxResourceSizeBytes']
        required = max(required, 6 * resource + 262144, email_transport_binary(max(1048576, resource)))
    if payload < required or effective['Messaging']['InlinePayloadThresholdBytes'] > payload:
        raise ValueError('Email payload declaration cannot contain source-derived envelope budgets')
    return {'database': [host, port, *names], 'blob': [provider, container, prefix, create],
            'worker': worker, 'effective': effective, 'jmap': jmap, 'dav': dav,
            'minimum_payload_bytes': required}


def email_transport_observe(captured):
    # Admit BOTH complete selected declaration sets before nested credentials.
    roles = ('worker', 'gateway')
    plans = {role: email_transport_plan(captured[role + '.json']) for role in roles}
    if (plans['worker']['database'][:3] != plans['gateway']['database'][:3]
            or plans['worker']['blob'][:3] != plans['gateway']['blob'][:3]):
        raise ValueError('declared Email pair must share exact database and Blob store')
    rows = [{'role': role, 'declaration_sha256': dep_hash.sha256(
                dep_json.dumps(plans[role], sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest(),
             'payload_bytes': plans[role]['effective']['Messaging']['MaxPayloadBytes'],
             'minimum_payload_bytes': plans[role]['minimum_payload_bytes']} for role in roles]
    return {'roles': rows, 'authority': {name: False for name in EMAIL_TRANSPORT_AUTHORITY}}

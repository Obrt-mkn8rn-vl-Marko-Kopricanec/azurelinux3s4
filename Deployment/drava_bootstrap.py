"""Admit a conservative unenrolled Drava bootstrap pair and opaque IPC identity."""


DRAVA_STATE = '/var/lib/mk8.drava/'
DRAVA_SOCKET = DRAVA_STATE + 'application/application.sock'
DRAVA_IPC_SOURCE = '/etc/mk8.drava/ipc-token.txt'
DRAVA_APPLICATION_FIELDS = ('schemaVersion', 'siteId', 'nodeId', 'gatewayId', 'stateDirectory',
    'listen', 'ingressAddress', 'httpPort', 'httpsPort', 'managementPort',
    'administratorTokenPath', 'maxConcurrentExchanges', 'controller')
DRAVA_GATEWAY_FIELDS = ('schemaVersion', 'gatewayId', 'siteId', 'bindAddress', 'httpPort',
    'httpsPort', 'registrationPort', 'managementPort', 'discoveryEnabled', 'stateDirectory',
    'application', 'plan', 'servingTrust', 'maxConcurrentExchanges', 'maxHeaderBytes',
    'maxRequestBodyBytes', 'requestBodyLimits', 'frameBytes', 'streamWindowFrames',
    'enrollmentRootFingerprint')
DRAVA_IPC_FIELDS = ('unixSocketPath', 'namedPipeName', 'httpsAddress', 'clientCertificatePath',
                    'trustedCertificatePath', 'identityTokenPath')
DRAVA_PLAN_BOUNDS = {'refreshSeconds': (5, 1, 60), 'retrySeconds': (1, 1, 30),
    'requestDeadlineSeconds': (3, 1, 15), 'maximumRetainedGenerations': (16, 2, 64),
    'tlsHandshakeSeconds': (5, 1, 30)}


def drava_record(value, fields):
    if type(value) is not dict or value.keys() - set(fields):
        raise ValueError('canonical Drava bootstrap record required')
    return value


def drava_integer(value, key, default, minimum, maximum):
    number = value.get(key, default)
    if type(number) is not int or not minimum <= number <= maximum:
        raise ValueError('bounded Drava integer declaration required')
    return number


def drava_identity(value):
    return deployment_text(value, r'[a-z0-9][a-z0-9._-]{0,127}', 128)


def drava_endpoint(value, role):
    endpoint = drava_record(value, DRAVA_IPC_FIELDS)
    expected = '/run/credentials/mk8-drava-' + role + '.service/ipc'
    if (endpoint.get('unixSocketPath') != DRAVA_SOCKET
            or endpoint.get('identityTokenPath') != expected
            or any(endpoint.get(key, '') != '' for key in
                   ('namedPipeName', 'httpsAddress', 'clientCertificatePath', 'trustedCertificatePath'))):
        raise ValueError('Drava application-state socket and literal role credential required')


def drava_bootstrap_observe(captured, plan):
    # Whole declaration admission precedes nested reads; nothing is selected/executed.
    application = drava_record(release_json(captured['application.json']), DRAVA_APPLICATION_FIELDS)
    gateway = drava_record(release_json(captured['gateway.json']), DRAVA_GATEWAY_FIELDS)
    for role, value, field in (('application', application, 'listen'), ('gateway', gateway, 'application')):
        drava_integer(value, 'schemaVersion', 1, 1, 1)
        drava_identity(value.get('siteId'))
        drava_identity(value.get('gatewayId', 'local'))
        if value.get('stateDirectory') != DRAVA_STATE + role:
            raise ValueError('Drava role-owned persistent state declaration required')
        drava_endpoint(value.get(field), role)
        drava_integer(value, 'maxConcurrentExchanges', 256, 1, 4096)
        if drava_integer(value, 'managementPort', 0, 0, 65535) != 0:
            raise ValueError('unenrolled Drava profile has no management listener')
    drava_identity(application.get('nodeId'))
    if (application['siteId'] != gateway['siteId']
            or application.get('gatewayId', 'local') != gateway.get('gatewayId', 'local')):
        raise ValueError('complete Drava pair identity correspondence required')
    if (application.get('controller') is not None or application.get('administratorTokenPath', '') != ''
            or gateway.get('enrollmentRootFingerprint', '') != ''
            or gateway.get('discoveryEnabled') is not False):
        raise ValueError('explicit unenrolled Drava declaration profile required')
    bind = gateway.get('bindAddress', '127.0.0.1')
    if (type(bind) is not str or bind not in ('127.0.0.1', '::1',
                                           *(row['address'] for row in plan['public']))
            or application.get('ingressAddress', '127.0.0.1') != bind):
        raise ValueError('Drava pair literal ingress declaration required')
    http = drava_integer(gateway, 'httpPort', 80, 1, 65535)
    if (http != 80 or drava_integer(application, 'httpPort', 80, 1, 65535) != http
            or drava_integer(gateway, 'httpsPort', 443, 0, 65535) != 0
            or drava_integer(application, 'httpsPort', 443, 0, 65535) != 0):
        raise ValueError('unenrolled Drava profile requires declared HTTP80 and HTTPS0')
    if drava_integer(gateway, 'registrationPort', 9443, 1, 65535) == http:
        raise ValueError('distinct declared Drava registration port required')
    drava_integer(gateway, 'maxHeaderBytes', 32768, 1024, 65536)
    drava_integer(gateway, 'maxRequestBodyBytes', 100 * 1024 * 1024, 0, 1024 ** 4)
    drava_integer(gateway, 'frameBytes', 32768, 1024, 32768)
    drava_integer(gateway, 'streamWindowFrames', 4, 1, 8)
    settings = drava_record(gateway.get('plan', {}), DRAVA_PLAN_BOUNDS)
    for key, bounds in DRAVA_PLAN_BOUNDS.items():
        drava_integer(settings, key, *bounds)
    trust = drava_record(gateway.get('servingTrust', {}), ('mode', 'rootFingerprint'))
    mode, fingerprint = trust.get('mode', 'site-ca'), trust.get('rootFingerprint', '')
    if (type(mode) is not str or mode not in ('site-ca', 'system', 'pinned')
            or type(fingerprint) is not str or (not dep_re.fullmatch(r'[0-9A-F]{64}', fingerprint)
            if mode == 'pinned' else fingerprint != '')):
        raise ValueError('canonical Drava serving trust declaration required')
    limits = gateway.get('requestBodyLimits', [])
    if type(limits) is not list or len(limits) > 64:
        raise ValueError('bounded Drava body-limit declarations required')
    seen = set()
    for row in limits:
        if type(row) is not dict or row.keys() != {'host', 'maxRequestBodyBytes'}:
            raise ValueError('complete Drava body-limit record required')
        host = row['host']
        if type(host) is not str or host != plan['domains']['mk8.drava'] or host in seen:
            raise ValueError('unique declared Drava host body limit required')
        drava_integer(row, 'maxRequestBodyBytes', 0, 0, 1024 ** 4)
        seen.add(host)
    token = deployment_read(DRAVA_IPC_SOURCE)
    # Narrower than .NET Trim(): one canonical ASCII token plus LF, raw<=256.
    if not dep_re.fullmatch(rb'[A-Za-z0-9_-]{32,255}\n', token):
        raise ValueError('bounded canonical Drava IPC token bytes required')
    for leaf in ('application.json', 'gateway.json'):
        if deployment_read('/etc/mk8.drava/' + leaf) != captured[leaf]:
            raise ValueError('Drava original bootstrap changed after nested observation')
    return {'source': DRAVA_IPC_SOURCE, 'bytes': len(token),
            'sha256': dep_hash.sha256(token).hexdigest(), 'mode': '0600'}

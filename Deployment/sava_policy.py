"""Bind a narrow original Sava account/key policy before inactive storage only."""


SAVA_POLICY_AUTHORITY = (
    'configuration_and_account_intent_authenticated', 'actual_dotnet_binding_proven',
    'key_entropy_and_crypto_usable', 'complete_sava_options_validated',
    'application_gateway_credential_access_proven', 'storage_identity_and_capacity_proven',
    'rpc_authentication_and_limits_enforced', 'public_anonymous_access_refusal_proven',
    'backup_restore_and_key_rotation_proven', 'application_ready',
)
SAVA_APPLICATION_BOUNDS = {
    'MaximumReadSessions': (256, 1, 65536),
    'MaximumConcurrentRpcRequests': (16, 1, 256),
    'MaximumQueuedRpcRequests': (128, 0, 4096),
}
SAVA_GATEWAY_BOUNDS = {
    'MaximumConcurrentRequests': (32, 1, 256),
    'MaximumQueuedRequests': (128, 0, 4096),
    'MaximumStagingBytes': (10737418240, 1, 10737418240),
}


def sava_key(value):
    if type(value) is not str or not dep_re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value):
        raise ValueError('canonical Sava base64 key required')
    raw = app_base64.b64decode(value, validate=True)
    if not 32 <= len(raw) <= 512 or app_base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('bounded canonical Sava key bytes required')
    return {'decoded_bytes': len(raw), 'encoded_sha256': dep_hash.sha256(value.encode('ascii')).hexdigest()}


def sava_limits(values, prefix, bounds):
    result = {}
    for key, (default, minimum, maximum) in bounds.items():
        text = values.get(prefix + key, str(default))
        if not dep_re.fullmatch(r'0|[1-9][0-9]{0,12}', text) or not minimum <= int(text) <= maximum:
            raise ValueError('bounded canonical Sava admission limit required')
        result[key] = int(text)
    return result


def application_sava_observe(candidate):
    original = {leaf: database_original('/etc/mk8.sava/' + leaf, candidate['configuration'])
                for leaf in ('policy.env', 'application.env', 'gateway.env', 'rpc.key')}
    common = application_environment(original['policy.env'], ('Sava__', 'ApplicationTransport__'))
    application = application_environment(original['application.env'], ('Sava__', 'ApplicationHosting__'))
    gateway = application_environment(original['gateway.env'], ('Gateway__',))
    accounts, encryption = {}, {}
    fixed = {'Sava__DefaultAccount', 'ApplicationTransport__Endpoint',
             'Sava__AllowAnonymousPublicAccess', 'Sava__EnableCrossAccountDeduplication'}
    for key, value in common.items():
        if key in fixed:
            continue
        prefix = 'Sava__Accounts__'
        account = key[len(prefix):] if key.startswith(prefix) else ''
        if not dep_re.fullmatch(r'[a-z0-9]{3,24}', account):
            raise ValueError('exact bounded Sava account policy surface required')
        accounts[account] = sava_key(value)
    if not 1 <= len(accounts) <= 32 or common.get('Sava__DefaultAccount') not in accounts:
        raise ValueError('Sava default must select one of the complete bounded account set')
    for key in ('Sava__AllowAnonymousPublicAccess', 'Sava__EnableCrossAccountDeduplication'):
        if common.get(key, 'false') != 'false':
            raise ValueError('Sava inactive profile requires explicit or default false public/dedup flags')
    allowed = {'Sava__DataPath', *('ApplicationHosting__' + key for key in SAVA_APPLICATION_BOUNDS)}
    for key, value in application.items():
        if key in allowed:
            continue
        prefix = 'Sava__DataEncryptionKeys__'
        account = key[len(prefix):] if key.startswith(prefix) else ''
        if account not in accounts:
            raise ValueError('Sava explicit data key must reference a declared account')
        encryption[account] = sava_key(value)
    # Repository subset requires explicit keys; the original source also permits
    # fallback to account keys. Neither choice authenticates key intent or rotation.
    if encryption.keys() != accounts.keys():
        raise ValueError('complete explicit Sava data-key declarations required')
    if gateway.keys() - {'Gateway__StagingPath', *('Gateway__' + key for key in SAVA_GATEWAY_BOUNDS)}:
        raise ValueError('exact selected Sava Gateway admission surface required')
    limits = {'application': sava_limits(application, 'ApplicationHosting__', SAVA_APPLICATION_BOUNDS),
              'gateway': sava_limits(gateway, 'Gateway__', SAVA_GATEWAY_BOUNDS)}
    rpc = sava_key(original['rpc.key'][:-1].decode('ascii'))
    for leaf, data in original.items():
        if deployment_read('/etc/mk8.sava/' + leaf) != data:
            raise ValueError('original Sava policy changed after admission')
    return {'default_account': common['Sava__DefaultAccount'],
            'accounts': [{'name': name, 'authentication_key': accounts[name], 'data_key': encryption[name]}
                         for name in sorted(accounts)], 'rpc_key': rpc, 'limits': limits,
            'sources': [{'file': '/etc/mk8.sava/' + leaf, 'bytes': len(data),
                         'sha256': dep_hash.sha256(data).hexdigest()} for leaf, data in original.items()],
            'authority': {name: False for name in SAVA_POLICY_AUTHORITY}}

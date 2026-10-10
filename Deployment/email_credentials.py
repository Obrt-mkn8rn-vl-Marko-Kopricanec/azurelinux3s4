"""Bind Email's literal nested file references to inactive per-unit credentials."""


EMAIL_CREDENTIAL_AUTHORITY = (
    'credential_intent_authenticated', 'secret_material_authenticated', 'key_roles_and_crypto_validated',
    'database_and_blob_credentials_usable', 'complete_environment_schema_validated',
    'actual_dotnet_deserialization_proven', 'service_identity_provisioned',
    'systemd_credential_delivery_proven', 'application_file_loading_proven',
    'tls_and_dkim_usable', 'credential_rotation_and_lifecycle_proven',
)
EMAIL_ROOT_FIELDS = frozenset(('Database', 'Smtp', 'Imap', 'Pop3', 'Sieve', 'Jmap', 'Dav', 'OAuth',
    'Mfa', 'Tls', 'Dkim', 'Security', 'Filtering', 'Queue', 'Limits', 'General', 'Admin', 'Messaging', 'ObjectStorage'))
EMAIL_RECORD_FIELDS = {
    'Database': ('Host', 'Port', 'Name', 'Username', 'Password', 'PasswordFile'),
    'OAuth': ('EnableOAuth', 'EnableOpenIdConnect', 'PublicBaseUrl', 'ClientId', 'AccessTokenMinutes',
              'RefreshTokenDays', 'AuthorizationCodeMinutes', 'IdTokenMinutes', 'SigningKey', 'SigningKeyFile'),
    'Mfa': ('EnableTotp', 'Issuer', 'EncryptionKey', 'EncryptionKeyFile', 'RecoveryCodeCount'),
    'Messaging': ('Enabled', 'EncryptionKeyId', 'EncryptionKey', 'EncryptionKeyFile', 'DecryptionKeys',
                  'MaxPayloadBytes', 'InlinePayloadThresholdBytes', 'LeaseSeconds', 'NotificationFallbackSeconds', 'WorkerId'),
    'ObjectStorage': ('Provider', 'ConnectionString', 'ConnectionStringFile', 'ContainerName', 'ObjectPrefix', 'CreateContainerIfMissing'),
    'Tls': ('CertificatePath', 'CertificateKeyPath'),
    'Dkim': ('PrivateKeyPath', 'Selector', 'EnableSigning'),
}
EMAIL_DECRYPTION_KEYS = 32
EMAIL_SECRET_LIMIT = 16384
EMAIL_ROLE_TOTAL = 256 * 1024


def email_record(value, fields):
    if type(value) is not dict or value.keys() - set(fields):
        raise ValueError('canonical Email credential record required')
    return value


def email_identifier(value):
    # Narrower than the original messaging identifier: safe fixed file basenames.
    if type(value) is not str or not dep_re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', value):
        raise ValueError('bounded canonical Email key identifier required')
    return value


def email_flag(value, name):
    flag = value.get(name, False)
    if type(flag) is not bool:
        raise ValueError('typed Email credential enablement required')
    return flag


def email_credential_plan(role, data):
    if role not in ('worker', 'gateway'):
        raise ValueError('explicit Email credential role required')
    value = email_record(release_json(data), EMAIL_ROOT_FIELDS)
    # Exact PascalCase selected records refuse the loader's case-insensitive aliases.
    records = {name: email_record(value.get(name, {}), fields)
               for name, fields in EMAIL_RECORD_FIELDS.items()}
    directory = '/run/credentials/mk8-email-' + role + '.service/'
    selected = {'config.json': ('/etc/mk8.email/' + role + '.json', data, 65536)}

    def secret(record, direct, reference, name, required=False):
        if record.get(direct, '') != '':
            raise ValueError('Email secrets must use exclusive file references')
        path = record.get(reference)
        if path is None and not required:
            return
        if path != directory + name:
            raise ValueError('literal role-owned Email credential path required')
        selected[name] = ('/etc/mk8.email/' + role + '/' + name, None, EMAIL_SECRET_LIMIT)

    secret(records['Database'], 'Password', 'PasswordFile', 'database-password.txt', True)
    messaging = records['Messaging']
    if not email_flag(messaging, 'Enabled'):
        raise ValueError('Email distributed messaging declaration required')
    seen = {email_identifier(messaging.get('EncryptionKeyId', 'primary'))}
    secret(messaging, 'EncryptionKey', 'EncryptionKeyFile', 'messaging-key.txt', True)
    keys = messaging.get('DecryptionKeys', [])
    if type(keys) is not list or len(keys) > EMAIL_DECRYPTION_KEYS:
        raise ValueError('bounded complete Email decryption-key list required')
    for key in keys:
        email_record(key, ('Id', 'Key', 'KeyFile'))
        identity = email_identifier(key.get('Id'))
        if identity in seen:
            raise ValueError('unique Email encryption/decryption identifiers required')
        seen.add(identity)
        secret(key, 'Key', 'KeyFile', 'messaging-decrypt-' + identity + '.txt', True)
    secret(records['ObjectStorage'], 'ConnectionString', 'ConnectionStringFile', 'blob-connection.txt', True)
    oauth, mfa, dkim = records['OAuth'], records['Mfa'], records['Dkim']
    email_flag(oauth, 'EnableOAuth')
    oidc, totp, signing = (email_flag(oauth, 'EnableOpenIdConnect'),
                           email_flag(mfa, 'EnableTotp'), email_flag(dkim, 'EnableSigning'))
    if role == 'worker':
        secret(oauth, 'SigningKey', 'SigningKeyFile', 'oauth-signing.txt', oidc)
        secret(mfa, 'EncryptionKey', 'EncryptionKeyFile', 'mfa-key.txt', totp)
        path = dkim.get('PrivateKeyPath')
        if signing or path is not None:
            if path != directory + 'dkim-key.pem':
                raise ValueError('worker-owned Email DKIM path required')
            selected['dkim-key.pem'] = ('/etc/mk8.email/worker/dkim-key.pem', None, EMAIL_SECRET_LIMIT)
    elif (oauth.get('SigningKey', '') != '' or oauth.get('SigningKeyFile') is not None
            or mfa.get('EncryptionKey', '') != '' or mfa.get('EncryptionKeyFile') is not None
            or dkim.get('PrivateKeyPath') is not None):
        raise ValueError('gateway cannot receive worker-only Email credentials')
    # Only the PEM pair is supported here. This does not parse or approve a key,
    # certificate, protocol enablement, persisted DB path or future rotation.
    tls = records['Tls']
    if tls.get('CertificatePath') is not None or tls.get('CertificateKeyPath') is not None:
        if (tls.get('CertificatePath') != directory + 'tls-certificate.pem'
                or tls.get('CertificateKeyPath') != directory + 'tls-key.pem'):
            raise ValueError('complete role-owned Email PEM path pair required')
        for name in ('tls-certificate.pem', 'tls-key.pem'):
            selected[name] = ('/etc/mk8.email/' + role + '/' + name, None, EMAIL_SECRET_LIMIT)
    return selected


def email_credential_observe(captured):
    roles = ('worker', 'gateway')
    # Validate BOTH full declaration sets before any new protected nested read.
    plans = {role: email_credential_plan(role, captured[role + '.json']) for role in roles}
    result = []
    for role in roles:
        rows, total = [], 0
        for name, (source, original, maximum) in sorted(plans[role].items()):
            data = deployment_read(source)
            total += len(data)
            if (not 0 < len(data) <= maximum or total > EMAIL_ROLE_TOTAL
                    or original is not None and data != original):
                raise ValueError('Email credential size or original configuration correspondence')
            rows.append({'id': name, 'source': source,
                         'destination': '/run/credentials/mk8-email-' + role + '.service/' + name,
                         'bytes': len(data), 'sha256': dep_hash.sha256(data).hexdigest()})
        result.append({'role': role, 'unit': 'mk8-email-' + role + '.service', 'inputs': rows,
                       'source_mode': '0600', 'checked_original_readback_and_close': True,
                       'authority': {name: False for name in EMAIL_CREDENTIAL_AUTHORITY}})
    return result


def email_credential_unit(plan):
    return tuple('LoadCredential=' + row['id'] + ':' + row['source'] for row in plan['inputs'])

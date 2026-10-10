"""Observe conservative Email protocol and URL declarations, without listeners."""


EMAIL_PRESENTATION_FIELDS = {
    'Smtp': ('Hostname', 'Port', 'SubmissionPort', 'ImplicitTlsPort', 'EnableSmtp',
             'EnableSubmission', 'EnableImplicitTls', 'EnableStartTls', 'RequireTls', 'RequireAuth', 'AllowRelay'),
    'Imap': ('Port', 'ImplicitTlsPort', 'EnableImap', 'EnableImplicitTls'),
    'Pop3': ('Port', 'ImplicitTlsPort', 'EnablePop3', 'EnableImplicitTls', 'EnableStartTls'),
    'Sieve': ('Port', 'EnableManageSieve', 'EnableStartTls', 'MaxScriptsPerUser'),
    'Security': ('PasswordHashScheme', 'EnableSpfCheck', 'EnableDmarcCheck'),
    'Jmap': EMAIL_TRANSPORT_FIELDS['Jmap'], 'Dav': EMAIL_TRANSPORT_FIELDS['Dav'],
    'OAuth': EMAIL_RECORD_FIELDS['OAuth'], 'Tls': EMAIL_RECORD_FIELDS['Tls'],
}
EMAIL_PRESENTATION_FLAGS = {
    'Smtp': {'EnableSmtp': True, 'EnableSubmission': False, 'EnableImplicitTls': False,
             'EnableStartTls': False, 'RequireTls': False, 'RequireAuth': True, 'AllowRelay': False},
    'Imap': {'EnableImap': True, 'EnableImplicitTls': False},
    'Pop3': {'EnablePop3': False, 'EnableImplicitTls': False, 'EnableStartTls': False},
    'Sieve': {'EnableManageSieve': False, 'EnableStartTls': True},
    'Security': {'EnableSpfCheck': False, 'EnableDmarcCheck': False},
    'Jmap': {'EnableJmap': True, 'IsDefault': True}, 'Dav': {'EnableDav': True},
    'OAuth': {'EnableOAuth': False, 'EnableOpenIdConnect': False},
}
EMAIL_PRESENTATION_PORTS = {
    'Smtp': {'Port': 25, 'SubmissionPort': 587, 'ImplicitTlsPort': 465},
    'Imap': {'Port': 143, 'ImplicitTlsPort': 993}, 'Pop3': {'Port': 110, 'ImplicitTlsPort': 995},
    'Sieve': {'Port': 4190},
}
EMAIL_PRESENTATION_AUTHORITY = (
    'complete_environment_schema_validated', 'actual_dotnet_deserialization_proven',
    'public_listener_assignment_proven', 'actual_mail_listeners_usable', 'actual_ipv6_mail_listeners_usable',
    'tls_keys_certificates_and_handshakes_proven', 'public_https_proxy_routes_admitted',
    'original_client_and_admin_enforcement_proven', 'mail_delivery_auth_and_relay_refusal_proven',
)


def email_presentation_url(value, expected):
    # A repository subset of the original HTTPS URI contract: no aliases,
    # userinfo, path, query, fragment, escapes, whitespace or alternate host.
    if value is not None and (type(value) is not str or value not in (expected, expected + '/')):
        raise ValueError('exact declared Email HTTPS origin required')
    return expected if value is None else value


def email_presentation_plan(data, role, plan):
    value = email_record(release_json(data), EMAIL_ROOT_FIELDS)
    records = {name: email_record(value.get(name, {}), fields)
               for name, fields in EMAIL_PRESENTATION_FIELDS.items()}
    flags = {name: {key: email_transport_boolean(records[name], key, default)
                    for key, default in fields.items()} for name, fields in EMAIL_PRESENTATION_FLAGS.items()}
    domain = plan['domains']['mk8.email']
    if records['Smtp'].get('Hostname', 'localhost') != domain:
        raise ValueError('Email SMTP hostname must equal declared mail domain')
    ports = {name: {key: email_transport_integer(records[name], key, default, 1, 65535)
                    for key, default in fields.items()} for name, fields in EMAIL_PRESENTATION_PORTS.items()}
    # Even disabled port declarations remain fixed and fully typed in this subset.
    if ports != EMAIL_PRESENTATION_PORTS:
        raise ValueError('fixed Email protocol port declarations required')
    email_transport_integer(records['Sieve'], 'MaxScriptsPerUser', 64, 1, 1000)
    http_port = email_transport_integer(records['Jmap'], 'Port', 8081, 1, 65535)
    expected = 'https://' + domain
    jmap = email_presentation_url(records['Jmap'].get('PublicBaseUrl'), expected)
    oauth = email_presentation_url(records['OAuth'].get('PublicBaseUrl'), expected)
    if (flags['Jmap']['IsDefault'] and not flags['Jmap']['EnableJmap']
            or flags['OAuth']['EnableOpenIdConnect'] and not flags['OAuth']['EnableOAuth']):
        raise ValueError('coherent Email JMAP and OAuth enablement required')
    if (records['Security'].get('PasswordHashScheme', 'BLF-CRYPT') != 'BLF-CRYPT'
            or flags['Security']['EnableSpfCheck'] or flags['Security']['EnableDmarcCheck']):
        raise ValueError('source-approved Email production security declarations required')
    if role == 'gateway':
        # Match this repository's fixed inactive firewall profile. The Worker
        # does not construct these presentation listeners in its original Main.
        smtp, imap, pop3, sieve = (flags[name] for name in ('Smtp', 'Imap', 'Pop3', 'Sieve'))
        if (not smtp['EnableSmtp'] or not smtp['EnableSubmission'] or not smtp['EnableStartTls']
                or not smtp['RequireAuth'] or smtp['EnableImplicitTls'] != plan['mail']['implicit_submission']
                or imap['EnableImap'] or not imap['EnableImplicitTls'] or pop3['EnablePop3']
                or pop3['EnableImplicitTls'] != plan['mail']['pop3s']
                or sieve['EnableManageSieve'] != plan['mail']['sieve']
                or sieve['EnableManageSieve'] and not sieve['EnableStartTls']):
            raise ValueError('Email gateway protocol declarations do not match fixed firewall profile')
        if http_port != plan['private_ports']['email_http']:
            raise ValueError('Email gateway HTTP declaration must match inactive unit port')
        directory = '/run/credentials/mk8-email-gateway.service/'
        if (records['Tls'].get('CertificatePath') != directory + 'tls-certificate.pem'
                or records['Tls'].get('CertificateKeyPath') != directory + 'tls-key.pem'):
            raise ValueError('complete literal gateway Email TLS file declarations required')
        public_ports = [25, 587, 993]
        public_ports.extend(port for enabled, port in ((smtp['EnableImplicitTls'], 465),
                           (pop3['EnableImplicitTls'], 995), (sieve['EnableManageSieve'], 4190)) if enabled)
    else:
        public_ports = []
    return {'role': role, 'declared_mail_ports': sorted(public_ports), 'jmap_origin': jmap,
            'oauth_origin': oauth, 'declared_http_port': http_port}


def email_presentation_observe(captured, plan):
    # Both original role sets precede any nested credential read. No candidate
    # field is added: their complete raw bytes already have accepted hash bindings.
    rows = [email_presentation_plan(captured[role + '.json'], role, plan)
            for role in ('worker', 'gateway')]
    return {'roles': rows, 'authority': {name: False for name in EMAIL_PRESENTATION_AUTHORITY}}

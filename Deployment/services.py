"""Produce inactive launch files only after complete release/input correspondence."""

import base64 as app_base64


APP_OUTPUT_LIMIT = 8 * 1024 * 1024
APP_AUTHORITY = (
    'owner_release_intent_authenticated', 'git_commit_tree_authenticated', 'release_publish_authenticated',
    'release_analyzers_passed', 'release_build_and_tests_passed', 'runtime_version_security_approved',
    'runtime_native_dependencies_usable', 'runtime_loader_resolution_proven', 'elf_or_managed_code_executed',
    'application_configuration_schema_validated', 'nested_credentials_admitted', 'runtime_credential_access_proven',
    'configuration_matches_network_and_storage_policy', 'service_accounts_provisioned', 'systemd_parser_validated',
    'sandbox_and_jit_compatibility_proven', 'service_units_installed', 'service_units_enabled',
    'services_started', 'application_readiness_proven', 'public_tls_usable', 'dns_publication_or_delegation_proven',
    'mail_delivery_and_relay_refusal_proven', 'postgresql_schema_and_roles_provisioned',
    'backup_restore_proven', 'update_rollback_and_reboot_proven', 'server_ready',
)


def application_environment(data, prefixes):
    # Narrow EnvironmentFile subset: no quotes, escapes, substitutions or newlines
    # in values. PID1 reads the original protected files; secrets never enter JSON.
    if (not data.endswith(b'\n') or any(byte < 32 and byte != 10 or byte > 126 for byte in data)):
        raise ValueError('bounded ASCII/LF application environment required')
    result = {}
    for line in data.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if (not separator or not dep_re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', key)
                or key in result or not any(key.startswith(prefix) for prefix in prefixes)
                or not dep_re.fullmatch(r'[A-Za-z0-9:/._+=,@;-]+', value)):
            raise ValueError('unsupported application EnvironmentFile declaration')
        result[key] = value
    if not result:
        raise ValueError('empty application environment')
    return result


def application_configuration(app, bindings, plan):
    result, captured = [], {}
    for leaf in REL_CONFIGS[app]:
        path = '/etc/' + app + '/' + leaf
        data = deployment_read(path)
        if dep_hash.sha256(data).hexdigest() != bindings[leaf]:
            raise ValueError('startup configuration digest mismatch')
        if leaf.endswith('.json') and type(release_json(data)) is not dict:
            raise ValueError('startup JSON object required')
        result.append({'file': path, 'bytes': len(data), 'sha256': bindings[leaf],
                       'mode': '0600', 'checked_readback_and_close': True})
        captured[leaf] = data
    if app == 'mk8.sava':
        common = application_environment(captured['policy.env'], ('Sava__', 'ApplicationTransport__'))
        application = application_environment(captured['application.env'], ('Sava__', 'ApplicationHosting__'))
        gateway = application_environment(captured['gateway.env'], ('Gateway__',))
        endpoint = 'http://127.0.0.1:' + str(plan['private_ports']['sava_application']) + '/internal/application'
        if (common.get('ApplicationTransport__Endpoint') != endpoint
                or 'ApplicationTransport__AccessKeyFile' in common
                or any(key.startswith('Sava__Data') for key in common)
                or common.keys() & application.keys()
                or application.get('Sava__DataPath') != '/var/lib/mk8.sava/application'
                or gateway.get('Gateway__StagingPath') != '/var/cache/mk8.sava-gateway/staging'):
            raise ValueError('Sava launch environment correspondence')
        key = captured['rpc.key']
        if not dep_re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}\n', key):
            raise ValueError('canonical RPC key encoding required')
        decoded = app_base64.b64decode(key[:-1], validate=True)
        if not 32 <= len(decoded) <= 512 or app_base64.b64encode(decoded) != key[:-1]:
            raise ValueError('RPC key size or encoding')
    if app == 'mk8.drava':
        # Only Application owns this cleanup-removable tree. The Gateway is a
        # consumer, never a second RuntimeDirectory owner. Full schemas remain open.
        for leaf, field in (('application.json', 'listen'), ('gateway.json', 'application')):
            endpoint = release_json(captured[leaf]).get(field)
            if (type(endpoint) is not dict
                    or endpoint.get('unixSocketPath') != '/run/mk8.drava/application.sock'
                    or endpoint.get('namedPipeName', '') != '' or endpoint.get('httpsAddress', '') != ''):
                raise ValueError('Drava application-owned Unix socket correspondence')
    if app == 'mk8.dns':
        # Controller is a publication client; the replica alone owns that socket.
        if (release_json(captured['control-plane.json']).get('PublicationSocket') !=
                '/run/mk8.dns/authoritative-replica/publication.sock'
                or release_json(captured['authority.json']).get('PublicationSocket') is not None):
            raise ValueError('DNS replica-owned publication socket correspondence')
    return result


def application_unit(name, app, role, release, arguments=(), extra=(), privileged=False, state=True, after=()):
    program = REL_PROGRAMS[app][role]
    directory = release['directory'] + '/' + role
    account = {'mk8.sava': 'mk8sava-' + role, 'mk8.drava': 'mk8drava',
               'mk8.dns': 'mk8dns', 'mk8.email': 'mk8email'}[app]
    lines = ['# Inactive candidate. Parser, JIT, accounts, credentials and health remain unproven.',
             '[Unit]', 'Description=' + name, 'Wants=network-online.target',
             'After=network-online.target' + ((' ' + ' '.join(after)) if after else ''),
             'StartLimitIntervalSec=120', 'StartLimitBurst=5', '', '[Service]',
             'Type=exec', 'User=' + account, 'Group=' + account, 'WorkingDirectory=' + directory,
             'ExecStart=' + directory + '/' + program + ((' ' + ' '.join(arguments)) if arguments else ''),
             'Environment=DOTNET_ENVIRONMENT=Production', 'Environment=ASPNETCORE_ENVIRONMENT=Production',
             'Environment=DOTNET_EnableDiagnostics=0', 'Restart=on-failure', 'RestartSec=5s',
             'TimeoutStartSec=120s', 'TimeoutStopSec=60s', 'KillMode=control-group', 'KillSignal=SIGTERM',
             'UMask=0077', 'LimitNOFILE=8192', 'TasksMax=512', 'MemoryMax=2G',
             'NoNewPrivileges=true', 'PrivateTmp=true', 'PrivateDevices=true', 'ProtectSystem=strict',
             'ProtectHome=true', 'ProtectKernelTunables=true', 'ProtectKernelModules=true',
             'ProtectKernelLogs=true', 'ProtectControlGroups=true', 'RestrictSUIDSGID=true',
             'RestrictRealtime=true', 'LockPersonality=true', 'SystemCallArchitectures=native',
             'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
             'CapabilityBoundingSet=' + ('CAP_NET_BIND_SERVICE' if privileged else ''),
             'AmbientCapabilities=' + ('CAP_NET_BIND_SERVICE' if privileged else ''),
             'StandardOutput=journal', 'StandardError=journal']
    if state:
        lines.extend(('StateDirectory=' + app, 'StateDirectoryMode=0700'))
    lines.extend(extra)
    lines.extend(('', '[Install]', 'WantedBy=multi-user.target', ''))
    return deployment_file('systemd/' + name + '.service', '0644', '\n'.join(lines))


def application_units(app, release, plan):
    config = '/etc/' + app + '/'
    if app == 'mk8.sava':
        common = ('EnvironmentFile=' + config + 'policy.env', 'LoadCredential=rpc-key:' + config + 'rpc.key',
                  'Environment=ApplicationTransport__AccessKeyFile=%d/rpc-key')
        return [application_unit('mk8-sava-application', app, 'application', release,
                    extra=common + ('EnvironmentFile=' + config + 'application.env',
                                    'StateDirectory=mk8.sava/application', 'StateDirectoryMode=0700'), state=False),
                application_unit('mk8-sava-gateway', app, 'gateway', release,
                    arguments=('--urls', 'http://127.0.0.1:' + str(plan['private_ports']['sava_gateway'])),
                    extra=common + ('EnvironmentFile=' + config + 'gateway.env',
                                    'CacheDirectory=mk8.sava-gateway', 'CacheDirectoryMode=0700',
                                    'InaccessiblePaths=-/var/lib/mk8.sava/application'), state=False,
                    after=('mk8-sava-application.service',))]
    if app == 'mk8.drava':
        return [application_unit('mk8-drava-' + role, app, role, release,
                    arguments=('--bootstrap', '%d/bootstrap.json'), privileged=role == 'gateway',
                    extra=('LoadCredential=bootstrap.json:' + config + role + '.json',) +
                          (('RuntimeDirectory=mk8.drava', 'RuntimeDirectoryMode=0700') if role == 'application' else ()),
                    after=('mk8-drava-application.service',) if role == 'gateway' else ())
                for role in ('application', 'gateway')]
    if app == 'mk8.email':
        return [application_unit('mk8-email-' + role, app, role, release,
                    arguments=('--serve',) if role == 'worker' else (), privileged=role == 'gateway',
                    extra=('LoadCredential=config.json:' + config + role + '.json',
                           'Environment=MK8EMAIL_CONFIG_FILE=%d/config.json',
                           'Environment=ASPNETCORE_URLS=http://127.0.0.1:' + str(plan['private_ports']['email_http']),
                           'Environment=ASPNETCORE_FORWARDEDHEADERS_ENABLED=false'),
                    after=('postgresql.service',)) for role in ('worker', 'gateway')]
    units = []
    for role, leaf in (('controller', 'control-plane.json'), ('authoritative-replica', 'authority.json')):
        runtime = 'mk8.dns/' + role
        arguments = ['--socket', '/run/' + runtime + '/control.sock', '--state', '/var/lib/mk8.dns/' + role,
                     '--node', 'r630-' + role, '--role', role, '--control', '%d/control.json']
        if role == 'authoritative-replica':
            arguments.extend(('--publication-socket', '/run/' + runtime + '/publication.sock'))
        units.append(application_unit('mk8-dns-' + role, app, 'application', release, arguments,
                     extra=('LoadCredential=control.json:' + config + leaf,
                            'RuntimeDirectory=' + runtime, 'RuntimeDirectoryMode=0700'), after=('postgresql.service',)))
    ports = set(plan['private_ports'].values())
    for index, listener in enumerate(plan['public']):
        port = plan['private_ports']['dns_health'] + index
        if port > 65535 or (index and port in ports):
            raise ValueError('distinct per-family DNS health port required')
        units.append(application_unit('mk8-dns-gateway' + str(listener['version']), app, 'gateway', release,
                     ('--socket', '/run/mk8.dns/authoritative-replica/control.sock', '--health-port', str(port),
                      '--dns-address', listener['address'], '--dns-port', '53'), privileged=True,
                     after=('mk8-dns-authoritative-replica.service',)))
    return units


def application_bundle(data, ssh_producer):
    candidate = deployment_bundle(data, ssh_producer)
    value, source = deployment_decode(data)
    plan = deployment_manifest(value)
    releases, configuration, units = [], [], []
    for app in DEP_APPS:
        observed = release_observe(app, plan['releases'][app])
        configuration.extend(application_configuration(app, observed['configuration'], plan))
        units.extend(application_units(app, observed, plan))
        releases.append(observed)
    result = {'schema': 1, 'source': source, 'deployment_candidate_sha256': dep_hash.sha256(
                  dep_json.dumps(candidate, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest(),
              'releases': releases, 'configuration': configuration, 'files': units,
              'authority': {name: False for name in APP_AUTHORITY}}
    if len(dep_json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii')) + 1 > APP_OUTPUT_LIMIT:
        raise ValueError('application candidate output bound')
    return result


def application_main(ssh_producer):
    try:
        if len(dep_sys.argv) != 2:
            raise ValueError('one protected deployment manifest required')
        dep_resource.setrlimit(dep_resource.RLIMIT_CPU, (120, 125))
        dep_resource.setrlimit(dep_resource.RLIMIT_AS, (384 * 1024 * 1024,) * 2)
        dep_resource.setrlimit(dep_resource.RLIMIT_CORE, (0, 0))
        result = application_bundle(deployment_read(dep_sys.argv[1]), ssh_producer)
        output = dep_json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
    except (OSError, ValueError, TypeError, MemoryError, RecursionError, OverflowError):
        print('Application service candidate refused', file=dep_sys.stderr)
        return 75
    print(output, end='')
    return 0

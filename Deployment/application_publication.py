"""Retain fresh complete application candidates in a separate inactive namespace."""


APP_PUB_STORE = '/var/lib/azurelinux3s4/application-candidates'
APP_PUB_LOCK = b'azurelinux3s4-inactive-application-publication-lock-v1\n'
APP_PUB_DIRECTORIES = ('helpers', 'systemd', 'sysusers')
APP_PUB_LIMIT = 16 * 1024 * 1024
APP_PUB_FILE_LIMIT = 64 * 1024
APP_PUB_BASE_UNITS = ('mk8-sava-application', 'mk8-sava-gateway',
                      'mk8-drava-application', 'mk8-drava-gateway',
                      'mk8-dns-controller', 'mk8-dns-authoritative-replica')


def application_publication_plan(data, ssh_producer):
    # Always reconstruct from protected original files. No candidate/receipt input.
    candidate = application_bundle(data, ssh_producer)
    value, source = deployment_decode(data)
    plan = deployment_manifest(value)
    names = (*APP_PUB_BASE_UNITS,
             *('mk8-dns-gateway' + str(row['version']) for row in plan['public']),
             'mk8-email-worker', 'mk8-email-gateway')
    expected = tuple('systemd/' + name + '.service' for name in names)
    if (candidate['source'] != source or type(candidate['files']) is not list
            or tuple(row['file'] for row in candidate['files']) != expected
            or candidate['authority'] != {name: False for name in APP_AUTHORITY}):
        raise ValueError('fresh complete inactive application candidate required')
    database = application_database_observe(candidate)
    sava = application_sava_observe(candidate)
    accounts = application_account_policy(candidate['files'])
    contents = {'manifest.json': data, 'candidate.json': publication_encoded(candidate)}
    rows = []
    helper = candidate['dns_credential_helper']
    payloads = [(row, row['file'], '0644') for row in candidate['files']]
    payloads.append((accounts['file'], 'sysusers/azurelinux3s4-applications.conf', '0644'))
    payloads.append((helper, 'helpers/dns-credentials.py', '0755'))
    for entry, stored, mode in payloads:
        deployment_fields(entry, ('file', 'mode', 'bytes', 'sha256', 'content'))
        if (type(entry['content']) is not str or type(entry['bytes']) is not int
                or entry['mode'] != mode or (stored.startswith('helpers/')
                and entry['file'] != DNS_CREDENTIAL_HELPER_PATH[1:])
                or (stored.startswith('sysusers/') and entry['file'] != APP_ACCOUNT_FILE)):
            raise ValueError('fixed application payload identity/mode required')
        raw = entry['content'].encode('ascii')
        if (not 0 < len(raw) <= APP_PUB_FILE_LIMIT or not raw.endswith(b'\n')
                or entry['bytes'] != len(raw) or entry['sha256'] != dep_hash.sha256(raw).hexdigest()
                or any(byte < 32 and byte not in (9, 10) or byte > 126 for byte in raw)):
            raise ValueError('application payload byte commitment mismatch')
        contents[stored] = raw
        rows.append({'stored': stored, **{name: entry[name] for name in ('file', 'mode', 'bytes', 'sha256')}})
    intent = publication_encoded({'format': 'azurelinux3s4-inactive-application-candidate-v1',
                                  'source': source, 'candidate': {'bytes': len(contents['candidate.json']),
                                  'sha256': dep_hash.sha256(contents['candidate.json']).hexdigest()},
                                  'files': rows, 'stored_leaf_mode': '0400', 'directory_mode': '0700',
                                  'database_profile_correspondence': database,
                                  'sava_policy_correspondence': sava,
                                  'service_account_policy': {name: accounts[name] for name in ('units', 'accounts', 'source_profile', 'authority', 'limits')},
                                  'activation_authorized': False})
    contents['publication.json'] = intent
    if len(contents) not in (14, 15) or sum(map(len, contents.values())) > APP_PUB_LIMIT:
        raise ValueError('complete application publication bound')
    return dep_hash.sha256(intent).hexdigest(), contents


def application_publication_publish(data, ssh_producer):
    return publication_publish(data, ssh_producer, planner=application_publication_plan,
                               store_path=APP_PUB_STORE, directories_profile=APP_PUB_DIRECTORIES,
                               lock_bytes=APP_PUB_LOCK)


def application_publication_main(ssh_producer):
    if len(dep_sys.argv) != 2:
        return 64
    try:
        dep_resource.setrlimit(dep_resource.RLIMIT_CPU, (150, 155))
        dep_resource.setrlimit(dep_resource.RLIMIT_AS, (384 * 1024 * 1024,) * 2)
        dep_resource.setrlimit(dep_resource.RLIMIT_CORE, (0, 0))
        path = dep_sys.argv[1]
        deployment_path(path)
        for store in (APP_PUB_STORE, PUB_STORE):
            if path == store or path.startswith(store + '/'):
                raise ValueError('original manifest must be outside inactive stores')
        output = publication_encoded(application_publication_publish(deployment_read(path), ssh_producer))
    except (OSError, ValueError, TypeError, AttributeError, MemoryError, RecursionError, OverflowError):
        print('Inactive application candidate publication refused', file=dep_sys.stderr)
        return 75
    print(output.decode('ascii'), end='')
    return 0

"""Disconnected owned-file installation for the five fixed deployment candidates.

No native parser, active service, firewall load, account or database operation is
provided. Installing these files would require separate operational authority.
"""


CONFIG_INSTALL_STATE = '/var/lib/azurelinux3s4/configuration-installation'
CONFIG_INSTALL_BASE = '/etc/azurelinux3s4'
CONFIG_INSTALL_LOCK = b'azurelinux3s4-configuration-file-installation-lock-v1\n'
CONFIG_INSTALL_DIRECTORIES = (CONFIG_INSTALL_STATE, CONFIG_INSTALL_BASE + '/ssh',
                              CONFIG_INSTALL_BASE + '/network', CONFIG_INSTALL_BASE + '/postgresql',
                              CONFIG_INSTALL_BASE + '/deployment')
CONFIG_INSTALL_AUTHORITY = ('operationally_authorized', 'configuration_intent_authenticated',
                           'topology_assigned', 'original_client_locality_proven',
                           'native_ssh_parser_passed', 'native_nft_parser_passed',
                           'native_postgresql_parser_passed', 'complete_existing_hooks_admitted',
                           'firewall_loaded', 'ssh_reloaded', 'postgresql_reloaded',
                           'accounts_or_databases_provisioned', 'services_started',
                           'boot_lifecycle_proven', 'physical_power_loss_proven', 'server_ready')
CONFIG_INSTALL_LIMITS = [
    'Disconnected library only; no production dispatcher/default installs or activates these configuration files.',
    'All five source payloads are freshly compiled from the original manifest. Every destination and exact owner is admitted before lock creation and again under the configuration-only cooperative lock.',
    'Destination directories must already exist with protected root ownership. Foreign files, changed plans and partial ownership records refuse without adoption, deletion or overwrite.',
    'Exact ownership permits completion of original 0600 prefixes, including private configuration whose final mode is also 0600; final readback still requires complete bytes.',
    'File visibility is sequential, not set-atomic. Failures may leave partial or complete bytes without success; a later independent consumer could read installed files.',
    'No native parsing, include/command-line/manager precedence, firewall transaction, PostgreSQL cluster/role/schema setup, SSH reload, rollback, boot persistence or physical durability is established.',
]


def configuration_installation_plan(data, ssh_producer):
    digest, contents = publication_plan(data, ssh_producer)
    intent, _ = deployment_decode(contents['publication.json'])
    _, source = deployment_decode(data)
    if (contents.keys() != {'manifest.json', 'candidate.json', 'publication.json', *PUB_FILES}
            or contents['manifest.json'] != data
            or digest != dep_hash.sha256(contents['publication.json']).hexdigest()
            or intent['format'] != 'azurelinux3s4-inactive-candidate-v1'
            or intent['activation_authorized'] is not False or intent['source'] != source
            or intent['candidate'] != {'bytes': len(contents['candidate.json']),
                                      'sha256': dep_hash.sha256(contents['candidate.json']).hexdigest()}
            or type(intent['files']) is not list or len(intent['files']) != len(PUB_FILES)):
        raise ValueError('fresh complete fixed configuration source required')
    rows = []
    for expected, entry in zip(PUB_FILES, intent['files']):
        deployment_fields(entry, ('file', 'mode', 'bytes', 'sha256'))
        mode = '0644' if expected == 'ssh/sshd_config' else '0600'
        raw = contents[expected]
        if (entry['file'] != expected or entry['mode'] != mode or type(entry['bytes']) is not int
                or type(raw) is not bytes or not 0 < len(raw) <= DEP_SOURCE_LIMIT
                or entry['bytes'] != len(raw) or entry['sha256'] != dep_hash.sha256(raw).hexdigest()
                or not raw.endswith(b'\n')):
            raise ValueError('fixed configuration payload commitment mismatch')
        group, leaf = expected.split('/')
        rows.append({'parent': CONFIG_INSTALL_BASE + '/' + group, 'leaf': leaf,
                     'mode': int(mode, 8), 'raw': raw})
    record = publication_encoded({'format': 'azurelinux3s4-configuration-file-installation-v1',
                                  'publication_sha256': digest, 'source': source, 'candidate': intent['candidate'],
                                  'files': [{'file': row['parent'] + '/' + row['leaf'],
                                             'mode': format(row['mode'], '04o'), 'bytes': len(row['raw']),
                                             'sha256': dep_hash.sha256(row['raw']).hexdigest()} for row in rows],
                                  'activation_authorized': False})
    if len(record) > DEP_SOURCE_LIMIT:
        raise ValueError('configuration installation ownership record bound')
    return digest, record, rows


def configuration_installation(data, ssh_producer):
    return installation_apply(data, ssh_producer, configuration=True)

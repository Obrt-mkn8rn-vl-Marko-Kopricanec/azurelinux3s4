"""Compile inactive PostgreSQL prerequisites; do not query or provision a server."""


PG_SOURCE_MINIMUM_VERSION = 170000
PG_SOCKET_DIRECTORY = '/run/postgresql'
PG_PROFILE_AUTHORITY = (
    'package_and_server_authenticated', 'current_native_version_and_features_proven',
    'native_configuration_parsed', 'complete_loaded_configuration_admitted',
    'unix_socket_identity_and_access_proven', 'tcp_loopback_only_enforced',
    'roles_and_passwords_provisioned', 'application_connection_strings_reconciled',
    'gateway_restricted_privileges_proven', 'application_schema_and_epoch_proven',
    'durability_and_backup_restore_proven', 'server_ready',
)


def postgresql_profile():
    # Original DNS uses one absolute Unix socket directory and demands all three
    # durability settings "on". Email's retained immutable role query uses the
    # PostgreSQL17 MAINTAIN privilege; a16 package declaration cannot close it.
    listener = ("listen_addresses = '127.0.0.1,::1'\n"
                "port = 5432\n"
                "password_encryption = 'scram-sha-256'\n"
                "unix_socket_directories = '/run/postgresql'\n"
                "fsync = on\nfull_page_writes = on\nsynchronous_commit = on\n")
    hba = ('local all postgres peer\n'
           'local mk8dns mk8dns scram-sha-256\n'
           'host mk8dns mk8dns 127.0.0.1/32 scram-sha-256\n'
           'host mk8dns mk8dns ::1/128 scram-sha-256\n'
           'host mk8email mk8email_worker,mk8email_gateway 127.0.0.1/32 scram-sha-256\n'
           'host mk8email mk8email_worker,mk8email_gateway ::1/128 scram-sha-256\n'
           'local all all reject\n'
           'host all all 0.0.0.0/0 reject\n'
           'host all all ::0/0 reject\n')
    # Future read-only native evidence must be freshly authenticated and checked;
    # these SQL bytes are never executed by this producer or its consumer.
    query = ("SELECT current_setting('server_version_num')::integer AS server_version_num,\n"
             "       current_setting('listen_addresses') AS listen_addresses,\n"
             "       current_setting('port')::integer AS port,\n"
             "       current_setting('unix_socket_directories') AS unix_socket_directories,\n"
             "       current_setting('fsync') AS fsync,\n"
             "       current_setting('full_page_writes') AS full_page_writes,\n"
             "       current_setting('synchronous_commit') AS synchronous_commit;\n")
    requirements = {
        'scope': 'UNSELECTED SOURCE PREREQUISITES; NO SERVER OBSERVATION OR PROVISIONING',
        'minimum_server_version_num': PG_SOURCE_MINIMUM_VERSION,
        'required_privilege_vocabulary': ['MAINTAIN'],
        'dns_controller': {'database': 'mk8dns', 'login_role': 'mk8dns',
                           'transport': 'one absolute Unix socket directory',
                           'host_directory': PG_SOCKET_DIRECTORY,
                           'requires_original_epoch_and_writer_lease': True},
        'email': {'database': 'mk8email', 'worker_login_role': 'mk8email_worker',
                  'gateway_login_role': 'mk8email_gateway', 'transport': 'loopback TCP',
                  'gateway_requires_authenticated_login_restricted_role_probe': True},
        'required_observed_settings': {'listen_addresses': '127.0.0.1,::1', 'port': 5432,
            'unix_socket_directories': PG_SOCKET_DIRECTORY, 'fsync': 'on',
            'full_page_writes': 'on', 'synchronous_commit': 'on'},
        'future_read_only_settings_query': {'sql': query,
            'bytes': len(query.encode('ascii')),
            'sha256': dep_policy_hash.sha256(query.encode('ascii')).hexdigest()},
        'prerequisites': [
            'Authenticate exact PostgreSQL package/server/native features;17+ is a necessary SOURCE floor, not exhaustive compatibility or selection.',
            'Create neither roles nor privileges from these names alone. Reconcile every actual DNS DSN and both Email original Database declarations/secrets with this separate prospective profile.',
            'The Gateway role must pass its complete original ownership/membership/default/ACL/catalog/routine probe after schema preparation; authentication rows grant no SQL privileges.',
            'Admit complete loaded conf/HBA/ident/role/database/schema/epoch context, socket ancestry and actual caller identity; loopback or Unix transport is not client-origin or credential-intent proof.',
            'Query text is inactive DATA. Values/modes/declarations do not prove fsync ordering, storage capacity, crash/power-loss durability, backup restoration or boot lifecycle.',
        ],
        'authority': {name: False for name in PG_PROFILE_AUTHORITY},
    }
    return (deployment_file('postgresql/listener.conf', '0600', listener),
            deployment_file('postgresql/pg_hba.conf', '0600', hba)), requirements

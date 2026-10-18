"""Parse exact private PostgreSQL settings without starting a database server.

Only fixed non-runtime-computed -C settings are queried in an uninitialized,
newly created private directory. HBA, SQL and authentication are not executed.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PARSER = '/usr/lib/postgresql/17/bin/postgres'
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'OPENSSL_CONF': '/dev/null'}
# Runtime-computed -C names can advance startup beyond the early exit. Never
# derive this query list from caller data, arbitrary config keys or a CLI flag.
SETTINGS = ('listen_addresses', 'port', 'password_encryption', 'unix_socket_directories',
            'fsync', 'full_page_writes', 'synchronous_commit')


def module(name):
    spec = importlib.util.spec_from_file_location('postgresql_preflight_' + name, ROOT/'Bootstrap'/(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PREFLIGHT = module('preflight')
NATIVE = module('native_tool')
RELEASE = NATIVE.RELEASE


def parser_input(candidate):
    namespace = RELEASE.contracts()
    path = ROOT/'Deployment/postgresql_profile.py'
    exec(compile(path.read_bytes(), str(path), 'exec'), namespace)
    rows, _ = namespace['postgresql_profile']()
    selected = [row for row in candidate['files'] if row['file'].startswith('postgresql/')]
    if selected != list(rows):
        raise ValueError('complete current PostgreSQL configuration bytes required')
    row = rows[0]; raw = row['content'].encode('ascii')
    if (not 0 < len(raw) <= 65536 or len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']
            or not raw.endswith(b'\n')):
        raise ValueError('bounded exact PostgreSQL configuration required')
    expected = {}
    for line in raw[:-1].decode('ascii').split('\n'):
        match = re.fullmatch(r"([a-z_]+) = (?:'([a-zA-Z0-9,./:-]+)'|([a-z0-9]+))", line)
        if not match or match[1] in expected or match[1] not in SETTINGS:
            raise ValueError('unsupported PostgreSQL parser-input syntax')
        expected[match[1]] = match[2] if match[2] is not None else match[3]
    if tuple(expected) != SETTINGS:
        raise ValueError('complete fixed PostgreSQL setting set required')
    return raw, expected, {'file': rows[1]['file'], 'bytes': rows[1]['bytes'], 'sha256': rows[1]['sha256'],
                           'native_hba_parsing_performed': False}


def create_fixture(directory, raw):
    for name, content in (('postgresql.conf', raw), ('postgresql.auto.conf', b'')):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        try:
            RELEASE.write_all(fd, content)
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)


def fixture_observation(directory):
    if RELEASE.names(directory, [0], 3) != ['postgresql.auto.conf', 'postgresql.conf']:
        raise ValueError('unexpected PostgreSQL private parser fixture object')
    result = {}
    for name in ('postgresql.conf', 'postgresql.auto.conf'):
        data, identity = RELEASE.read_file(directory, name, 65536, capture=True)
        if stat.S_IMODE(identity[2]) != 0o400 or name == 'postgresql.auto.conf' and data[0] != 0:
            raise ValueError('exact owner-only PostgreSQL parser inputs required')
        result[name] = {'bytes': data[0], 'sha256': data[1], 'identity': list(identity)}
    return result


def audit(private_root, manifest, work_parent, parser_sha256):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    private_root, work_parent = (Path(RELEASE.absolute(path)) for path in (private_root, work_parent))
    if work_parent == private_root or work_parent.is_relative_to(private_root):
        raise ValueError('parser scratch must be outside the source root')
    before = PREFLIGHT.preflight(private_root, manifest, kind='deployment', include_candidate=True)
    raw, expected, hba = parser_input(before['candidate'])
    with contextlib.ExitStack() as stack:
        links = []
        parent = RELEASE.anchor(stack, str(work_parent), links); info = os.fstat(parent)
        if info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private owned 0700 parser work parent required')
        native = NATIVE.PinnedExecutable(stack, parser_sha256, path=PARSER, label='postgres',
                                        environment=ENVIRONMENT, timeout=10)
        version = native.run(['--version']).decode('ascii')
        if native.last_stderr or not re.fullmatch(r'postgres \(PostgreSQL\) 17\.[0-9]+(?: [ -~]+)?\n', version):
            raise ValueError('selected PostgreSQL 17 development parser required')
        with tempfile.TemporaryDirectory(prefix='postgres-parser-', dir=work_parent) as temporary:
            with contextlib.ExitStack() as fixture_stack:
                fixture_links = []
                directory = RELEASE.anchor(fixture_stack, temporary, fixture_links)
                create_fixture(directory, raw)
                baseline = fixture_observation(directory); identity = RELEASE.identity(os.fstat(directory))
                if baseline['postgresql.conf']['sha256'] != hashlib.sha256(raw).hexdigest():
                    raise ValueError('private parser copy differs')
                observed = {}
                for name in SETTINGS:
                    if fixture_observation(directory) != baseline:
                        raise ValueError('PostgreSQL parser fixture changed')
                    value = native.run(['-D', temporary, '-C', name])
                    if native.last_stderr or value != (expected[name] + '\n').encode('ascii'):
                        raise ValueError('native PostgreSQL setting differs: ' + name)
                    observed[name] = value.decode('ascii').removesuffix('\n')
                if fixture_observation(directory) != baseline or RELEASE.identity(os.fstat(directory)) != identity:
                    raise ValueError('PostgreSQL parser fixture changed')
                if PREFLIGHT.preflight(private_root, manifest, kind='deployment', include_candidate=True) != before:
                    raise ValueError('deployment plan changed during PostgreSQL parsing')
                RELEASE.check_links(fixture_links); RELEASE.check_links(links); native.check()
                result = {'scope': 'PRIVATE DEVELOPMENT POSTGRESQL CONFIGURATION PARSING',
                          'software_sha256': before['software_sha256'], 'manifest_sha256': before['manifest_sha256'],
                          'publication_sha256': before['publication_sha256'],
                          'configuration': {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
                          'hba_commitment_only': hba, 'settings': observed, 'fixture': baseline,
                          'parser': {'path': PARSER, 'sha256': parser_sha256, 'version': version,
                                     'identity': list(RELEASE.identity(native.before)), 'commands': native.commands},
                          'checks': {'exact_current_configuration': True, 'all_seven_native_settings_match': True,
                                     'private_fixture_unchanged': True, 'full_source_plan_reobserved': True},
                          'authority': {'vendor_and_dependencies_authenticated': False, 'target_parser_passed': False,
                                        'native_hba_parsed': False, 'roles_or_schema_provisioned': False,
                                        'sql_or_authentication_executed': False, 'server_started': False,
                                        'socket_or_loopback_enforcement_proven': False, 'durability_proven': False,
                                        'published_or_installed': False, 'network_or_gpu_changed': False, 'server_ready': False},
                          'limits': ['Only seven fixed non-runtime-computed -C names are queried. This selects the early configuration-only exit before data/control checks, PID locking, preload libraries, shared memory and listener startup.',
                                     'The exact listener.conf bytes are parsed as private postgresql.conf, with a separate empty private postgresql.auto.conf. No initdb, cluster, PG_VERSION, SQL, HBA parser, database or socket is supplied.',
                                     'Current HBA bytes are bound as unparsed DATA only. Role existence, password/peer authentication, database privileges/schema, actual server invocation and loaded configuration remain open.',
                                     'Local parser output and fsync declarations do not prove target/vendor/shared-library authentication, effective running settings, durable storage, crash recovery or power-loss behavior.',
                                     'Inputs and executable are reobserved sequentially. Trusted native code, ordinary deadlines and private developer ancestry are not atomicity, hostile same-UID isolation or hard blocked-IO progress guarantees.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'work-parent', 'parser-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.manifest, args.work_parent, args.parser_sha256)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Private PostgreSQL configuration check refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

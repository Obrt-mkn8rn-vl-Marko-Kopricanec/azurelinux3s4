"""Dry-run exact application sysusers declarations against private account data.

Only a newly created developer fixture is supplied to systemd-sysusers. Its
numeric proposals are observations, not reserved IDs or account authorization.
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
PARSER = '/usr/bin/systemd-sysusers'
DATABASES = {'passwd': 0o644, 'group': 0o644, 'shadow': 0o600, 'gshadow': 0o600, 'nsswitch.conf': 0o644}
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'SYSTEMD_LOG_TARGET': 'console',
               'SYSTEMD_LOG_LEVEL': 'info', 'SYSTEMD_COLORS': '0', 'SYSTEMD_URLIFY': '0',
               'SYSTEMD_PAGER': 'cat', 'SYSTEMD_PAGERSECURE': '1'}


def module(name):
    spec = importlib.util.spec_from_file_location('account_preflight_' + name, ROOT/'Bootstrap'/(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PREFLIGHT = module('preflight')
NATIVE = module('native_tool')
RELEASE = NATIVE.RELEASE


def allocation_range(value):
    if type(value) is not str or not re.fullmatch(r'[1-9][0-9]{0,4}-[1-9][0-9]{0,4}', value):
        raise ValueError('explicit canonical allocation range required')
    lower, upper = map(int, value.split('-'))
    if not 1 <= lower <= upper < 65534:
        raise ValueError('bounded non-root allocation range required')
    return lower, upper


def inputs(before):
    observation = before['account_observation']
    if (not observation['selected_nss_files_only']
            or any(row['status'] not in ('absent', 'compatible-local-declarations') for row in observation['accounts'])):
        raise ValueError('conflicting or nonlocal account declarations')
    namespace, software = PREFLIGHT.shipped_library()
    if software != before['software_sha256']:
        raise ValueError('software changed before account compilation')
    policy = namespace['application_account_policy'](before['candidate']['files'])
    if [row['name'] for row in policy['accounts']] != [row['name'] for row in observation['accounts']]:
        raise ValueError('complete account unit correspondence required')
    raw = policy['file']['content'].encode('ascii')
    published = next(row for row in before['files'] if row['file'] == 'sysusers/azurelinux3s4-applications.conf')
    if published['bytes'] != len(raw) or published['sha256'] != hashlib.sha256(raw).hexdigest():
        raise ValueError('exact current sysusers publication commitment required')
    return raw, observation, namespace


def write_file(parent, name, content):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        RELEASE.write_all(fd, content); os.fchmod(fd, 0o400)
    finally:
        os.close(fd)


def fixture_snapshot(root, etc):
    if (RELEASE.names(root, [0], 4) != ['allocation.conf', 'applications.conf', 'etc']
            or RELEASE.names(etc, [0], 6) != sorted(DATABASES)):
        raise ValueError('unexpected account parser fixture object')
    result = {}
    for parent, prefix, names in ((root, '', ('allocation.conf', 'applications.conf')), (etc, 'etc/', DATABASES)):
        for name in names:
            raw, identity = RELEASE.read_file(parent, name, 2 * 1024 * 1024, capture=True)
            if stat.S_IMODE(identity[2]) != 0o400:
                raise ValueError('owner-only account parser copies required')
            result[prefix + name] = {'bytes': raw[0], 'sha256': raw[1], 'identity': list(identity)}
    return result


def reconcile(raw, observation, databases, bounds):
    if type(raw) is not bytes or len(raw) > NATIVE.OUTPUT_LIMIT:
        raise ValueError('bounded native account dry-run output required')
    groups, users, writes = {}, {}, []
    for line in raw.decode('ascii').splitlines():
        group = re.fullmatch(r"Creating group '([a-z0-9-]+)' with GID ([1-9][0-9]*)\.", line)
        user = re.fullmatch(r"Creating user '([a-z0-9-]+)' \(Application service account\) with UID ([1-9][0-9]*) and GID ([1-9][0-9]*)\.", line)
        write = re.fullmatch(r'Would write /etc/(group|gshadow|passwd|shadow)\.\.\.', line)
        if group and group[1] not in groups:
            groups[group[1]] = int(group[2])
        elif user and user[1] not in users:
            users[user[1]] = (int(user[2]), int(user[3]))
        elif write:
            writes.append(write[1])
        else:
            raise ValueError('unsupported or duplicate native account diagnostic')
    missing = {row['name'] for row in observation['accounts'] if row['status'] == 'absent'}
    if set(groups) != missing or set(users) != missing or writes != (['group', 'gshadow', 'passwd', 'shadow'] if missing else []):
        raise ValueError('native account dry-run membership differs')
    occupied = {int(row[2]) for row in databases['passwd'].values()} | {int(row[3]) for row in databases['passwd'].values()}
    occupied.update(int(row[2]) for row in databases['group'].values())
    selected = set(); rows = []
    for row in observation['accounts']:
        name = row['name']
        if name in missing:
            uid, gid = users[name]
            if uid != gid or groups[name] != gid or not bounds[0] <= uid <= bounds[1] or uid in occupied or uid in selected:
                raise ValueError('native numeric proposal conflicts or leaves explicit range')
            selected.add(uid)
            rows.append({'name': name, 'status': 'would-create', 'uid': uid, 'gid': gid})
        else:
            rows.append({'name': name, 'status': 'existing-local-declarations', 'uid': row['uid'], 'gid': row['gid']})
    return rows


def audit(private_root, manifest, work_parent, parser_sha256, proposed_range):
    bounds = allocation_range(proposed_range)
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    private_root, work_parent = (Path(RELEASE.absolute(path)) for path in (private_root, work_parent))
    if work_parent == private_root or work_parent.is_relative_to(private_root):
        raise ValueError('parser scratch must be outside the source root')
    before = PREFLIGHT.preflight(private_root, manifest, kind='accounts', include_candidate=True)
    raw, observation, namespace = inputs(before)
    with contextlib.ExitStack() as stack:
        links = []
        source = RELEASE.anchor(stack, str(private_root/'etc'), links)
        captured, identities = {}, {}
        for name, mode in DATABASES.items():
            data, identity = RELEASE.read_file(source, name, 2 * 1024 * 1024, capture=True)
            if (stat.S_IMODE(identity[2]) != mode
                    or observation['sources'][name] != {'bytes': data[0], 'sha256': data[1]}):
                raise ValueError('fresh account source commitment or mode differs')
            captured[name], identities[name] = data[2], identity
        databases = {name: namespace['account_rows'](captured[name], name) for name in ('passwd', 'group')}
        if (databases['passwd'].get('root', [None]*7)[2:4] != ['0', '0']
                or databases['group'].get('root', [None]*4)[2] != '0'):
            raise ValueError('explicit private root account baseline required')
        parent = RELEASE.anchor(stack, str(work_parent), links); info = os.fstat(parent)
        if info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private owned 0700 parser work parent required')
        native = NATIVE.PinnedExecutable(stack, parser_sha256, path=PARSER, label='systemd-sysusers',
                                        environment=ENVIRONMENT, timeout=10)
        version = native.run(['--version']).decode('ascii')
        if native.last_stderr or not re.match(r'systemd (255|257)\b', version):
            raise ValueError('selected systemd 255 or 257 development parser required')
        with tempfile.TemporaryDirectory(prefix='account-parser-', dir=work_parent) as temporary:
            stage = Path(temporary); (stage/'etc').mkdir(mode=0o700)
            with contextlib.ExitStack() as fixture_stack:
                fixture_links = []
                fixture_root = RELEASE.anchor(fixture_stack, temporary, fixture_links)
                fixture_etc = RELEASE.anchor(fixture_stack, str(stage/'etc'), fixture_links)
                allocation = ('r - ' + proposed_range + '\n').encode('ascii')
                write_file(fixture_root, 'allocation.conf', allocation); write_file(fixture_root, 'applications.conf', raw)
                for name, content in captured.items(): write_file(fixture_etc, name, content)
                baseline = fixture_snapshot(fixture_root, fixture_etc)
                original_directories = [RELEASE.identity(os.fstat(fd)) for fd in (fixture_root, fixture_etc)]
                # Explicit absolute source paths are not rebased by --root.
                # --root restricts local account lookups; no default fragments,
                # replacement search, image, inline or credential input is used.
                native.run(['--dry-run', '--root=' + temporary, '--no-pager',
                            str(stage/'allocation.conf'), str(stage/'applications.conf')])
                if native.last_stdout:
                    raise ValueError('unexpected native account stdout')
                proposals = reconcile(native.last_stderr, observation, databases, bounds)
                if (fixture_snapshot(fixture_root, fixture_etc) != baseline
                        or [RELEASE.identity(os.fstat(fd)) for fd in (fixture_root, fixture_etc)] != original_directories):
                    raise ValueError('native account dry-run changed its fixture')
                for name in DATABASES:
                    data, _ = RELEASE.read_file(source, name, 2 * 1024 * 1024, capture=True, expected=identities[name])
                    if data[2] != captured[name]: raise ValueError('original account source changed')
                if PREFLIGHT.preflight(private_root, manifest, kind='accounts', include_candidate=True) != before:
                    raise ValueError('application or account plan changed during dry-run')
                RELEASE.check_links(fixture_links); RELEASE.check_links(links); native.check()
                result = {'scope': 'PRIVATE DEVELOPMENT ACCOUNT DRY-RUN', 'software_sha256': before['software_sha256'],
                          'manifest_sha256': before['manifest_sha256'], 'publication_sha256': before['publication_sha256'],
                          'configuration': {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
                          'explicit_allocation_range': {'lower': bounds[0], 'upper': bounds[1],
                              'supplemental_bytes': len(allocation), 'supplemental_sha256': hashlib.sha256(allocation).hexdigest()},
                          'account_sources': observation['sources'], 'proposals': proposals, 'fixture': baseline,
                          'parser': {'path': PARSER, 'sha256': parser_sha256, 'version': version,
                              'identity': list(RELEASE.identity(native.before)), 'commands': native.commands,
                              'dry_run_diagnostics': native.last_stderr.decode('ascii')},
                          'checks': {'exact_application_fragment': True, 'complete_native_proposals_match': True,
                                     'private_fixture_unchanged': True, 'full_source_plan_reobserved': True},
                          'authority': {'vendor_and_dependencies_authenticated': False, 'target_parser_passed': False,
                                        'host_nss_observed': False, 'uids_reserved_or_authorized': False,
                                        'accounts_created_or_adopted': False, 'password_or_shell_enforcement_proven': False,
                                        'credential_or_service_access_proven': False, 'published_or_installed': False,
                                        'network_or_gpu_changed': False, 'server_ready': False},
                          'limits': ['The exact application fragment is accompanied by a separate explicit caller range file in a disposable private root. Proposed IDs are dry-run observations, never allocation authority or future reservation.',
                                     'Only the five original private account files are copied, with whole source commitments. Conflicts or non-files NSS declarations refuse before native parsing. No host account database or additional sysusers fragment is adopted.',
                                     'The native --dry-run mode skips account locks and writes. Alternate-root lookups use the private local databases; fixed environment supplies no systemd credential directory. Whole fixture bytes, modes and identities are rechecked.',
                                     'Existing compatible declarations are neither authorized adoption nor actual NSS/password/PAM/shell/credential/service enforcement. Native syntax and proposals are not installed target/vendor/library or full precedence proof.',
                                     'Sequential checks, trusted native/base/private ancestry and ordinary deadlines do not prove atomicity, hostile same-UID isolation, future custody or hard blocked-IO progress.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'work-parent', 'parser-sha256', 'allocation-range'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.manifest, args.work_parent, args.parser_sha256, args.allocation_range)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Private account dry-run refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

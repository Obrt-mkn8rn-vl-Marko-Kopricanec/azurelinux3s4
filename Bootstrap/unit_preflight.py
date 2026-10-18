"""Parse exact candidate units in a disposable private native systemd fixture.

No running manager is contacted. Executable leaves are explicitly non-runnable
parser placeholders; this check neither starts an application nor proves that
its executable, dependencies, accounts or installed configuration are usable.
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
PARSER = '/usr/bin/systemd-analyze'
PLACEHOLDER = b'PARSER-FIXTURE-ONLY: not an executable file format\n'
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'SYSTEMD_LOG_TARGET': 'console',
               'SYSTEMD_LOG_LEVEL': 'warning', 'SYSTEMD_COLORS': '0', 'SYSTEMD_URLIFY': '0',
               'SYSTEMD_PAGER': 'cat', 'SYSTEMD_PAGERSECURE': '1', 'SYSTEMD_UNIT_PATH': '/etc/systemd/system'}


def module(name):
    spec = importlib.util.spec_from_file_location('unit_preflight_' + name, ROOT/'Bootstrap'/(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PREFLIGHT = module('preflight')
NATIVE = module('native_tool')
RELEASE = NATIVE.RELEASE


class ParserRefusal(ValueError):
    def __init__(self, native):
        super().__init__('local unit parser refused the exact candidate')
        self.commands = list(native.commands)
        self.stdout = native.last_stdout[:NATIVE.OUTPUT_LIMIT]
        self.stderr = native.last_stderr[:NATIVE.OUTPUT_LIMIT]


def parser_inputs(candidate):
    contract = RELEASE.contracts()
    releases = candidate['releases']
    if type(releases) is not list or [row['app'] for row in releases] != list(contract['DEP_APPS']):
        raise ValueError('complete ordered release declarations required')
    allowed = {'/usr/bin/python3'}
    for release in releases:
        app, commit = release['app'], release['declaration']['commit']
        if type(commit) is not str or not re.fullmatch('[0-9a-f]{40}', commit):
            raise ValueError('exact release identity required')
        directory = '/opt/' + app + '/releases/' + commit
        if release['directory'] != directory:
            raise ValueError('exact release directory required')
        allowed.update(directory + '/' + role + '/' + program for role,program in contract['REL_PROGRAMS'][app].items())
    units = candidate['files']
    if type(units) is not list or len(units) not in (9, 10):
        raise ValueError('complete unit input set required')
    selected, executables = {}, set()
    for row in units:
        name = row['file']
        if (type(name) is not str or not re.fullmatch(r'systemd/mk8-[a-z0-9-]+\.service', name)
                or name in selected or row['mode'] != '0644' or type(row['content']) is not str):
            raise ValueError('fixed unique candidate unit required')
        raw = row['content'].encode('ascii')
        if (type(row['bytes']) is not int or not 0 < row['bytes'] <= 65536 or len(raw) != row['bytes']
                or hashlib.sha256(raw).hexdigest() != row['sha256']):
            raise ValueError('complete unit byte commitments required')
        selected[name] = raw
        main_commands = 0
        for line in row['content'].splitlines():
            key, separator, value = line.partition('=')
            if separator and key.startswith('Exec'):
                executable = value.split(' ', 1)[0]
                if key not in ('ExecStart', 'ExecStartPre') or executable not in allowed:
                    raise ValueError('fixed declared parser-fixture executable required')
                main_commands += key == 'ExecStart'
                executables.add(executable)
        if main_commands != 1:
            raise ValueError('one application command per candidate unit required')
    return selected, sorted(executables)


def create_file(root, logical, raw, mode):
    path = root/logical.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        RELEASE.write_all(fd, raw)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def tree(root):
    # This is an owned newly-created parser fixture, not caller-supplied content.
    files, directories = {}, []
    for path in sorted(root.rglob('*')):
        info = path.lstat(); relative = str(path.relative_to(root))
        if stat.S_ISDIR(info.st_mode):
            directories.append(relative)
        elif stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1:
            raw = path.read_bytes()
            files[relative] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                               'mode': format(stat.S_IMODE(info.st_mode), '04o')}
        else:
            raise ValueError('unexpected private parser fixture object')
    return {'files': files, 'directories': directories}


def audit(private_root, manifest, work_parent, parser_sha256):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    private_root = Path(RELEASE.absolute(private_root))
    work_parent = Path(RELEASE.absolute(work_parent))
    if work_parent == private_root or work_parent.is_relative_to(private_root):
        raise ValueError('parser scratch must be outside the source root')
    before = PREFLIGHT.preflight(private_root, manifest, include_candidate=True)
    units, executables = parser_inputs(before['candidate'])
    with contextlib.ExitStack() as stack:
        links = []
        parent = RELEASE.anchor(stack, str(work_parent), links)
        info = os.fstat(parent)
        if (info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('private owned 0700 parser work parent required')
        with tempfile.TemporaryDirectory(prefix='unit-parser-', dir=work_parent) as temporary:
            stage = Path(temporary)
            for name, raw in units.items():
                create_file(stage, '/etc/systemd/system/' + name.removeprefix('systemd/'), raw, 0o400)
            for executable in executables:
                create_file(stage, executable, PLACEHOLDER, 0o500)
            empty = stage/'empty-generators'; empty.mkdir(mode=0o700)
            environment = {**ENVIRONMENT, 'SYSTEMD_GENERATOR_PATH': str(empty),
                           'SYSTEMD_ENVIRONMENT_GENERATOR_PATH': str(empty)}
            native = NATIVE.PinnedExecutable(stack, parser_sha256, path=PARSER, label='systemd-analyze',
                                            environment=environment, timeout=20)
            version = native.run(['--version']).decode('ascii')
            if not re.match(r'systemd (255|257)\b', version):
                raise ValueError('selected systemd 255 or 257 development parser required')
            expected = tree(stage)
            arguments = ['--root=' + str(stage), '--man=no', '--generators=no', '--recursive-errors=no',
                         '--no-pager', 'verify', *(name.removeprefix('systemd/') for name in units)]
            try:
                native.run(arguments)
            except ValueError as error:
                raise ParserRefusal(native) from error
            if native.last_stderr or native.last_stdout or tree(stage) != expected:
                raise ValueError('unit parser emitted diagnostics or changed its fixture')
            if PREFLIGHT.preflight(private_root, manifest, include_candidate=True) != before:
                raise ValueError('application plan changed during native unit parsing')
            native.check(); RELEASE.check_links(links)
            result = {'scope': 'PRIVATE DEVELOPMENT UNIT SYNTAX', 'software_sha256': before['software_sha256'],
                      'manifest_sha256': before['manifest_sha256'], 'publication_sha256': before['publication_sha256'],
                      'units': [{'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                                for name,raw in units.items()],
                      'parser': {'path': PARSER, 'sha256': parser_sha256, 'version': version,
                                 'identity': list(RELEASE.identity(native.before)), 'commands': native.commands},
                      'fixture': expected, 'placeholder_executables': executables,
                      'checks': {'exact_current_unit_bytes': True, 'native_unit_parser': True,
                                 'no_parser_diagnostics': True, 'full_source_plan_reobserved': True},
                      'authority': {'installed_vendor_parser_authenticated': False, 'target_parser_passed': False,
                                    'native_account_or_credential_access_proven': False, 'dependency_graph_usable': False,
                                    'executables_or_application_runtime_usable': False, 'manager_loaded_units': False,
                                    'published_or_installed': False, 'network_or_gpu_changed': False, 'server_ready': False},
                      'limits': ['Local pinned developer systemd parser only, not selected target/vendor/shared-library authentication.',
                                 'All exact unit bytes are parsed. Dependency recursion is deliberately disabled; executables are non-runnable private placeholders. No dependency, executable, account, credential or sandbox usability follows.',
                                 'Both generator searches point solely to an empty private directory, unit generators and man-page checks are disabled, and unit lookup is restricted to the private root. No daemon reload/start/enable or running-manager API is supplied.',
                                 'The native parser may allocate its own temporary directories. Only this tool-owned scratch tree is removed; original application inputs are reobserved without modification.',
                                 'Sequential checks, caller SHA pins, ordinary native deadlines and trusted development code do not prove atomicity, hostile same-UID isolation, hard blocked-IO progress or actual service lifecycle.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'work-parent', 'parser-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.manifest, args.work_parent, args.parser_sha256)
    except ParserRefusal as error:
        print('Private unit syntax check refused', file=sys.stderr)
        # Unit declarations are source text, never raw credential bodies. Keep
        # parser diagnostics available without emitting a partial JSON success.
        sys.stderr.write(error.stderr.decode('utf-8', 'replace'))
        return 75
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Private unit syntax check refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

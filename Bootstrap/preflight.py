"""Run shipped candidate admission against a private developer tree, read-only.

Logical /etc and /opt paths refer only to the explicit private root. This is an
offline configuration check, not native parsing, installed-root admission or an
application/service execution. It does not publish the resulting candidate.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def module(name):
    spec = importlib.util.spec_from_file_location('preflight_' + name, ROOT / 'Bootstrap' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def shipped_library():
    pack = module('pack')
    outputs = pack.artifacts()
    for name, expected in outputs.items():
        path = pack.target_path(ROOT, name)
        if path.read_bytes() != expected or stat.S_IMODE(path.stat().st_mode) != pack.OUTPUTS[name]:
            raise ValueError('generated software differs from maintained sources or modes')
    script = outputs[pack.TARGET].decode('utf-8')
    marker = 's4_ssh_candidate() {\n'
    if script.count(marker) != 1:
        raise ValueError('one shipped shared candidate function required')
    program = script.split(marker, 1)[1].split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0] + '\n'
    dispatch = '\naction = sys.argv[1]\n'
    if program.count(dispatch) != 1:
        raise ValueError('known shipped dispatcher boundary required')
    library = program.split(dispatch, 1)[0] + '\n'
    namespace = {'__name__': 'private_root_preflight'}
    exec(compile(library, 'shipped-candidate-library', 'exec'), namespace)
    return namespace, {name: hashlib.sha256(raw).hexdigest() for name, raw in outputs.items()}


class ReadOnlyRoot:
    """FD-only access to one held root; no host absolute paths or write APIs."""

    CONSTANTS = {'O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY', 'SEEK_SET'}

    def __init__(self, root):
        self.root = root
        self.live = set()

    def __getattr__(self, name):
        if name in self.CONSTANTS:
            return getattr(os, name)
        raise AttributeError('private preflight has no such OS capability')

    def owned(self, fd):
        if type(fd) is not int or fd not in self.live:
            raise ValueError('private preflight requires its own descriptor')
        return fd

    def leaf(self, value):
        if type(value) is not str or not value or '/' in value or value in ('.', '..'):
            raise ValueError('private preflight requires a single relative path component')
        return value

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        allowed = READ | os.O_DIRECTORY
        if type(flags) is not int or flags & ~allowed or flags & READ != READ:
            raise ValueError('private preflight permits checked read-only opens only')
        if path == '/' and dir_fd is None:
            fd = os.open('.', flags, dir_fd=self.root)
        else:
            fd = os.open(self.leaf(path), flags, dir_fd=self.owned(dir_fd))
        self.live.add(fd)
        return fd

    def close(self, fd):
        self.owned(fd)
        self.live.remove(fd)
        os.close(fd)

    def fstat(self, fd):
        return os.fstat(self.owned(fd))

    def stat(self, path, *, dir_fd=None, follow_symlinks=False):
        if follow_symlinks is not False:
            raise ValueError('private preflight refuses symlink traversal')
        return os.stat(self.leaf(path), dir_fd=self.owned(dir_fd), follow_symlinks=False)

    def read(self, fd, size):
        return os.read(self.owned(fd), size)

    def lseek(self, fd, offset, whence):
        return os.lseek(self.owned(fd), offset, whence)

    def scandir(self, fd):
        return os.scandir(self.owned(fd))

    def geteuid(self):
        return os.geteuid()

    def finish(self):
        if self.live:
            # Cleanup is best-effort only on an already failed path. Any leftover
            # descriptor on a nominal return makes the whole preflight refuse.
            failures = []
            for fd in tuple(self.live):
                self.live.remove(fd)
                try:
                    os.close(fd)
                except OSError as error:
                    failures.append(error)
            raise ValueError('private preflight left unfinished descriptor ownership') from (failures[0] if failures else None)


def denied(*args, **kwargs):
    raise ValueError('private preflight cannot invoke publication, installation or native mutation')


class NoNativeOperations:
    def __getattr__(self, name):
        raise ValueError('private preflight cannot invoke native publication operations')


def preflight(private_root, manifest, kind='applications', include_candidate=False):
    if os.geteuid() == 0 or os.getegid() != os.geteuid():
        raise ValueError('unprivileged developer with matching file UID/GID required')
    if kind not in ('deployment', 'applications') or type(include_candidate) is not bool:
        raise ValueError('explicit supported preflight selection required')
    release = module('release')
    namespace, software = shipped_library()
    namespace['deployment_path'](manifest)
    with contextlib.ExitStack() as stack:
        links = []
        root = release.anchor(stack, release.absolute(private_root), links)
        before = os.fstat(root)
        if (before.st_uid != os.geteuid() or before.st_gid != os.getegid()
                or stat.S_IMODE(before.st_mode) != 0o700):
            raise ValueError('preflight root must be a developer-owned private 0700 directory')
        bridge = ReadOnlyRoot(root)
        namespace['dep_os'] = bridge
        namespace['DEP_TRUSTED_UID'] = os.geteuid()
        namespace['pub_fcntl'] = NoNativeOperations()
        namespace['pub_ctypes'] = NoNativeOperations()
        for name in ('publication_publish', 'application_publication_publish', 'application_installation',
                     'application_rollback', 'application_reinstallation', 'publication_store'):
            namespace[name] = denied
        try:
            original = namespace['deployment_read'](manifest)
            planner = namespace['publication_plan'] if kind == 'deployment' else namespace['application_publication_plan']
            digest, contents = planner(original, namespace['bundle'])
            if namespace['deployment_read'](manifest) != original:
                raise ValueError('preflight original manifest changed')
            if release.identity(os.fstat(root)) != release.identity(before):
                raise ValueError('private preflight root changed')
            release.check_links(links)
        finally:
            bridge.finish()
        result = {'scope': 'PRIVATE DEVELOPMENT PREFLIGHT', 'kind': kind, 'software_sha256': software,
                  'manifest_sha256': hashlib.sha256(original).hexdigest(), 'publication_sha256': digest,
                  'files': [{'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                            for name, raw in contents.items()],
                  'authority': {'host_root_observed': False, 'source_or_configuration_authenticated': False,
                                'native_parsers_executed': False, 'accounts_provisioned': False,
                                'application_executed': False, 'published': False, 'installed': False,
                                'network_or_gpu_changed': False, 'server_ready': False},
                  'limits': ['The explicit developer root and current UID stand in for prospective host root/ownership; this is not installed-host evidence.',
                             'All ordinary maintained manifest/release/configuration/credential/unit/account admission remains active. Only the dispatcher and OS delivery context are replaced.',
                             'No publication/native/file-installation capability is provided. Repeated read observations remain sequential, not atomic or hostile same-UID protection.']}
        if include_candidate:
            result['candidate'] = json.loads(contents['candidate.json'])
            result['publication'] = json.loads(contents['publication.json'])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, help='existing private developer root, never /')
    parser.add_argument('--manifest', required=True, help='logical absolute path inside the private root')
    parser.add_argument('--kind', choices=('deployment', 'applications'), default='applications')
    parser.add_argument('--include-candidate', action='store_true', help='include candidate declarations and file text on stdout')
    args = parser.parse_args(argv)
    try:
        result = preflight(args.root, args.manifest, args.kind, args.include_candidate)
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'))
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError('private preflight output bound')
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError, OverflowError):
        print('Private development preflight refused', file=sys.stderr)
        return 75
    print(raw)
    return 0


if __name__ == '__main__':
    sys.exit(main())

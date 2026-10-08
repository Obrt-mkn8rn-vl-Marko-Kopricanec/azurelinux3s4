"""Native RPM ordering of observed removal pairs, never installation policy."""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import stat
import sys


VERSION_PROBES = (
    ('2', '1', 1), ('1.10', '1.9', 1), ('1.01', '1.1', 0),
    ('1.0~rc1', '1.0', -1), ('1.0^git', '1.0', 1),
    ('1.0^git', '1.0.1', -1), ('2.azl3', '1.azl3', 1), ('9', '10', -1), ('1', '1.0', -1),
)
VERSION_LIMIT = 32 * 1024 * 1024


def version_evr(name, nevra, architecture):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]{0,255}', name)
            or not isinstance(nevra, str) or len(nevra) > 1024 or not nevra.startswith(name + '-')
            or architecture not in ('x86_64', 'aarch64', 'noarch')):
        raise ValueError('unsupported replacement version identity')
    match = re.fullmatch(r'(?:(0|[1-9][0-9]{0,9}):)?([A-Za-z0-9._+~^]+)-([A-Za-z0-9._+~^]+)\.'
                         + re.escape(architecture), nevra[len(name) + 1:])
    if not match or int(match[1] or '0') > 2**32 - 1:
        raise ValueError('replacement version is outside the supported canonical EVR subset')
    return match[1] or '0', match[2], match[3]


def version_native():
    if (platform.machine() not in ('x86_64', 'aarch64')
            or C.sizeof(C.c_void_p) != 8 or C.sizeof(C.c_ulong) != 8 or C.sizeof(C.c_int) != 4):
        raise ValueError('unsupported native RPM comparison ABI')
    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, 'RPMVERSION').value != b'4.18.2':
        raise ValueError('native RPM comparison version has not been vetted')
    try:
        compare = lib.rpmvercmp
    except AttributeError as error:
        raise ValueError('native RPM comparison function is missing') from error
    compare.argtypes, compare.restype = (C.c_char_p, C.c_char_p), C.c_int
    def checked(left, right):
        result = compare(left.encode('ascii'), right.encode('ascii'))
        if type(result) is not int or result not in (-1, 0, 1):
            raise ValueError('native RPM comparison returned an unsupported result')
        return result
    return checked


def version_observe(proof, comparator_factory=version_native):
    guard = proof['removal_guard']
    if (not isinstance(guard, dict) or type(guard.get('schema')) is not int or guard['schema'] != 1
            or guard.get('same_name_architecture_replacements_only') is not True
            or guard.get('kernel_removals_refused') is not True
            or any(guard.get(flag) is not False for flag in (
                'versions_compared_by_guard', 'package_continuity_proven', 'critical_package_closure_complete',
                'removal_policy_satisfied', 'rollback_policy_satisfied', 'installation_authorized'))
            or not isinstance(guard.get('matches'), list) or len(guard['matches']) > 128):
        raise ValueError('current replacement correspondence guard is missing or excessive')
    # Production calls the unchanged correspondence guard first on a fresh
    # native TEST proof. This helper is not independent proof authentication.
    pairs = [(value, version_evr(value['name'], value['removed_nevra'], value['architecture']),
              version_evr(value['name'], value['replacement_nevra'], value['architecture']))
             for value in guard['matches']]
    compare = comparator_factory()
    def checked(left, right):
        result = compare(left, right)
        if type(result) is not int or result not in (-1, 0, 1):
            raise ValueError('replacement comparison has unsupported result')
        return result
    controls = []
    for left, right, expected in VERSION_PROBES:
        observed = [checked(left, right), checked(right, left), checked(left, left), checked(right, right)]
        if observed != [expected, -expected, 0, 0]:
            raise ValueError('native RPM ordering participation control failed')
        controls.append({'left': left, 'right': right, 'observed': observed})
    matches = []
    for value, old, new in pairs:
        decisions = []
        for label, left, right in zip(('epoch', 'version', 'release'), new, old):
            forward, reverse = checked(left, right), checked(right, left)
            if reverse != -forward: raise ValueError('native ordering is not reversible')
            decisions.append({'component': label, 'incoming': left, 'installed': right, 'result': forward})
            if forward: break
        if decisions[-1]['result'] != 1:
            raise ValueError('replacement pair is a downgrade or version-equivalent reinstall')
        matches.append({**value, 'removed_evr': list(old), 'replacement_evr': list(new), 'comparisons': decisions})
    proof['replacement_version_guard'] = {
        'schema': 1, 'matches': matches, 'pairs_compared': len(matches), 'ordering_controls': controls,
        'native_ordering_controls_passed': True, 'observed_replacement_pairs_strictly_newer': bool(matches),
        'scope': 'native epoch/version/release order of SAME-name/architecture current TEST erasure pairs ONLY',
        **{name: False for name in ('all_incoming_versions_checked', 'kernel_version_policy_satisfied',
            'installed_baseline_authenticated', 'native_library_identity_authenticated', 'package_continuity_proven',
            'freshness_proven', 'anti_rollback_proven', 'removal_policy_satisfied', 'rollback_policy_satisfied',
            'installation_authorized', 'installs_performed', 'scripts_executed', 'server_ready')},
    }
    return proof


def version_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def version_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate version proof field')
        result[key] = value
    return result


def version_main(correspondence_guard, incoming_guard=None):
    if len(sys.argv) != 2: return 64
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        path = Path(sys.argv[1]) / 'result.json'; before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= VERSION_LIMIT):
            raise ValueError('version proof is not a bounded private regular snapshot')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as stream:
            if version_identity(os.fstat(stream.fileno())) != version_identity(before):
                raise ValueError('version proof changed before reading')
            data = stream.read(VERSION_LIMIT + 1)
            if (len(data) != before.st_size or version_identity(os.fstat(stream.fileno())) != version_identity(before)
                    or version_identity(path.lstat()) != version_identity(before)):
                raise ValueError('version proof changed during reading')
        proof = version_observe(correspondence_guard(json.loads(data, object_pairs_hook=version_unique)))
        if incoming_guard is not None:
            proof = incoming_guard(proof)
        digest = hashlib.sha256(data).hexdigest()
        proof['removal_guard']['input_sha256'] = proof['replacement_version_guard']['input_sha256'] = digest
        if incoming_guard is not None:
            proof['incoming_version_guard']['input_sha256'] = digest
        encoded = json.dumps(proof, sort_keys=True)
        if len(encoded.encode()) > 64 * 1024 * 1024: raise ValueError('version observations exceed output bound')
        print(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, OverflowError, IndexError, StopIteration) as error:
        print('Update replacement version safeguard deferred: ' + str(error), file=sys.stderr)
        return 75

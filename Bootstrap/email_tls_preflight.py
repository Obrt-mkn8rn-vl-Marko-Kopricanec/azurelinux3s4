"""Check the private application's exact Email TLS sources with local OpenSSL.

The complete shipped application plan is reconstructed before and after the
cryptographic checks. No application, listener, publication or installation runs.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location('email_preflight_' + name, ROOT/'Bootstrap'/(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PREFLIGHT = module('preflight')
TLS = module('tls_inputs')


def selected_roles(candidate):
    observations = candidate['email_credentials']
    if type(observations) is not list or [row['role'] for row in observations] != ['worker', 'gateway']:
        raise ValueError('complete ordered Email credential plans required')
    selected = []
    for row in observations:
        role = row['role']
        if row['unit'] != 'mk8-email-' + role + '.service' or type(row['inputs']) is not list:
            raise ValueError('fixed Email unit credential correspondence required')
        found = {}
        for item in row['inputs']:
            name = item['id']
            if name not in ('tls-certificate.pem', 'tls-key.pem'):
                continue
            if (name in found or item['source'] != '/etc/mk8.email/' + role + '/' + name
                    or item['destination'] != '/run/credentials/mk8-email-' + role + '.service/' + name
                    or type(item['bytes']) is not int or not 0 < item['bytes'] <= 16384
                    or type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
                raise ValueError('exact source-bound Email TLS credential row required')
            found[name] = item
        if (found or role == 'gateway') and found.keys() != {'tls-certificate.pem', 'tls-key.pem'}:
            raise ValueError('complete configured Email TLS pair required')
        if found:
            selected.append((role, {kind: found[name] for kind, name in
                                   (('certificate', 'tls-certificate.pem'), ('key', 'tls-key.pem'))}))
    return selected


def audit(private_root, manifest, anchors, openssl_sha256, intermediates=None, at=None, minimum_seconds=86400):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    current = int(time.time()) if at is None else at
    root_path = Path(TLS.RELEASE.absolute(private_root))
    # This validates logical path syntax before joining; no traversal or absolute
    # host-path substitution is admitted by the private-root mapping.
    contract = TLS.RELEASE.contracts()
    parts = contract['deployment_path'](manifest)
    with contextlib.ExitStack() as stack:
        links = []
        root = TLS.RELEASE.anchor(stack, str(root_path), links)
        root_identity = TLS.RELEASE.identity(os.fstat(root))
        captured_manifest = TLS.private_input(stack, links, root_path.joinpath(*parts))
        original = captured_manifest[2][2]
        before = PREFLIGHT.preflight(root_path, manifest, include_candidate=True)
        if before['manifest_sha256'] != hashlib.sha256(original).hexdigest():
            raise ValueError('Email TLS preflight manifest changed')
        value, _ = contract['deployment_decode'](original)
        domain = contract['deployment_manifest'](value)['domains']['mk8.email']
        selected = selected_roles(before['candidate'])
        trust_paths = {'anchors': anchors}
        if intermediates is not None: trust_paths['intermediates'] = intermediates
        captured_trust = {name: TLS.private_input(stack, links, path) for name,path in trust_paths.items()}
        trust_commitments = {name: {'bytes': row[2][0], 'sha256': row[2][1]}
                             for name,row in captured_trust.items()}
        results = []
        for role, rows in selected:
            expected = {**trust_commitments, **{name: {key: row[key] for key in ('bytes', 'sha256')}
                                                for name,row in rows.items()}}
            checked = TLS.audit(domain, root_path/rows['certificate']['source'][1:],
                                root_path/rows['key']['source'][1:], anchors, openssl_sha256,
                                intermediates, current, minimum_seconds, expected_sources=expected)
            results.append({'role': role, 'unit': 'mk8-email-' + role + '.service',
                            'source_paths': {name: row['source'] for name,row in rows.items()}, 'tls': checked})
        after = PREFLIGHT.preflight(root_path, manifest, include_candidate=True)
        if before != after:
            raise ValueError('complete application plan changed during TLS checks')
        for parent, filename, raw, identity in (captured_manifest, *captured_trust.values()):
            again, _ = TLS.RELEASE.read_file(parent, filename, TLS.INPUT_LIMIT, capture=True, expected=identity)
            if again != raw:
                raise ValueError('Email TLS preflight original source changed')
        if TLS.RELEASE.identity(os.fstat(root)) != root_identity:
            raise ValueError('Email TLS preflight root identity changed')
        TLS.RELEASE.check_links(links)
        result = {'scope': 'PRIVATE APPLICATION EMAIL TLS PREFLIGHT', 'domain': domain,
                  'evaluation_unix_seconds': current, 'explicit_time_supplied': at is not None,
                  'software_sha256': before['software_sha256'], 'manifest_sha256': before['manifest_sha256'],
                  'publication_sha256': before['publication_sha256'], 'files': before['files'], 'roles': results,
                  'authority': {'host_root_observed': False, 'release_or_configuration_authenticated': False,
                                'vendor_runtime_authenticated': False, 'application_loaded_credentials': False,
                                'tls_handshake_proven': False, 'published': False, 'installed': False,
                                'network_or_gpu_changed': False, 'server_ready': False},
                  'limits': ['Complete shipped application admission remains active; synthetic or actual developer-owned inputs do not establish installed-root or release intent.',
                             'Only the TLS pairs named by the fresh Email credential plans are checked. Same full plan is rebuilt afterward; observations remain sequential, not atomic or hostile same-UID protection.',
                             'Explicit local OpenSSL checks are neither .NET credential loading nor application startup, listener, handshake, trust-intent, revocation, CT or current-clock proof.',
                             'No publication, account, system trust, service, network, GPU or target operation is supplied. Native library and provider authenticity remain open.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'anchors', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--intermediates')
    parser.add_argument('--at', type=int)
    parser.add_argument('--minimum-seconds', type=int, default=86400)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.manifest, args.anchors, args.openssl_sha256,
                       args.intermediates, args.at, args.minimum_seconds)
        output = json.dumps(result, sort_keys=True, separators=(',', ':'))
        if len(output) > 1024 * 1024: raise ValueError('Email TLS preflight output bound')
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Private Email TLS preflight refused', file=sys.stderr)
        return 75
    print(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())

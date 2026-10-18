"""Bind four release signatures to the complete fresh private application plan.

The trust policy is an original private file pinned by the caller. All source
declarations are admitted before native verification; nothing is installed.
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
POLICY_FIELDS = {'attestation', 'signature', 'public_key', 'public_key_sha256', 'minimum_sequence'}


def module(name):
    spec = importlib.util.spec_from_file_location('application_attestations_' + name, ROOT/'Bootstrap'/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PREFLIGHT = module('preflight')
ATTEST = module('release_attestation')
INPUTS = ATTEST.INPUTS
RELEASE = ATTEST.RELEASE


def trust_policy(raw, contract):
    value, _ = contract['deployment_decode'](raw)
    contract['deployment_fields'](value, ('schema', 'applications'))
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('explicit release trust policy schema required')
    contract['deployment_fields'](value['applications'], contract['DEP_APPS'])
    names = []
    for app in contract['DEP_APPS']:
        row = value['applications'][app]
        contract['deployment_fields'](row, POLICY_FIELDS)
        if (type(row['public_key_sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', row['public_key_sha256'])
                or type(row['minimum_sequence']) is not int or not 1 <= row['minimum_sequence'] < 2**63):
            raise ValueError('explicit per-application key pin and sequence floor required')
        for name in ('attestation', 'signature', 'public_key'):
            if type(row[name]) is not str:
                raise ValueError('explicit public attestation input paths required')
            RELEASE.absolute(row[name])
        names.extend((row['attestation'], row['signature']))
    if len(set(names)) != len(names):
        raise ValueError('distinct application attestation and signature paths required')
    return value['applications']


def audit(private_root, manifest, policy, policy_sha256, openssl_sha256, at=None):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    if type(policy_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', policy_sha256):
        raise ValueError('explicit original trust policy pin required')
    current = int(time.time()) if at is None else at
    root_path = Path(RELEASE.absolute(private_root))
    contract = RELEASE.contracts()
    manifest_parts = contract['deployment_path'](manifest)
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack, str(root_path), links)
        root_identity = RELEASE.identity(os.fstat(root))
        manifest_source = INPUTS.private_input(stack, links, root_path.joinpath(*manifest_parts))
        policy_source = INPUTS.private_input(stack, links, policy)
        if policy_source[2][1] != policy_sha256:
            raise ValueError('original release trust policy differs from the explicit caller pin')
        policy_rows = trust_policy(policy_source[2][2], contract)
        before = PREFLIGHT.preflight(root_path, manifest, include_candidate=True)
        if before['manifest_sha256'] != manifest_source[2][1]:
            raise ValueError('application attestation original manifest changed')
        value, _ = contract['deployment_decode'](manifest_source[2][2])
        plan = contract['deployment_manifest'](value)
        observed = before['candidate']['releases']
        if type(observed) is not list or [row['app'] for row in observed] != list(contract['DEP_APPS']):
            raise ValueError('complete ordered application release observations required')
        sources, arguments = {}, {}
        for app, observation in zip(contract['DEP_APPS'], observed):
            declaration = plan['releases'][app]
            logical = '/opt/' + app + '/releases/' + declaration['commit']
            if (observation['declaration'] != declaration or observation['directory'] != logical
                    or observation['manifest_sha256'] != declaration['manifest_sha256']):
                raise ValueError('candidate release differs from original manifest declaration')
            row = policy_rows[app]
            captured = sources[app] = {name: INPUTS.private_input(stack, links, row[name])
                                      for name in ('attestation', 'signature', 'public_key')}
            key = captured['public_key'][2][2]
            if (len(key) != 44 or not key.startswith(ATTEST.ED25519_SPKI)
                    or captured['public_key'][2][1] != row['public_key_sha256']
                    or captured['signature'][2][0] != 64):
                raise ValueError('complete pinned application signature inputs required')
            ATTEST.envelope(captured['attestation'][2][2], app, declaration['commit'], declaration['tree'],
                            declaration['manifest_sha256'], row['public_key_sha256'], row['minimum_sequence'], current)
            arguments[app] = {'app': app, **declaration, 'release': root_path/logical[1:],
                              **row, 'openssl_sha256': openssl_sha256, 'at': current,
                              'expected_sources': {name: {'bytes': source[2][0], 'sha256': source[2][1]}
                                                   for name, source in captured.items()}}
        # All four complete original policies, declarations and public sources
        # are admitted before the first native signature verification.
        results = [ATTEST.audit(**arguments[app]) for app in contract['DEP_APPS']]
        after = PREFLIGHT.preflight(root_path, manifest, include_candidate=True)
        if after != before:
            raise ValueError('complete application plan changed during attestation checks')
        for source in (manifest_source, policy_source, *(row for rows in sources.values() for row in rows.values())):
            parent, leaf, original, identity = source
            fresh, _ = RELEASE.read_file(parent, leaf, INPUTS.INPUT_LIMIT, capture=True, expected=identity)
            if fresh != original:
                raise ValueError('original application attestation source changed')
        if RELEASE.identity(os.fstat(root)) != root_identity:
            raise ValueError('application attestation private root changed')
        RELEASE.check_links(links)
        result = {'scope': 'PRIVATE FOUR-APPLICATION RELEASE SIGNATURE PREFLIGHT',
                  'software_sha256': before['software_sha256'], 'manifest_sha256': before['manifest_sha256'],
                  'publication_sha256': before['publication_sha256'], 'files': before['files'],
                  'trust_policy': {'bytes': policy_source[2][0], 'sha256': policy_source[2][1],
                                   'identity': list(policy_source[3])},
                  'evaluation_unix_seconds': current, 'explicit_time_supplied': at is not None,
                  'applications': results,
                  'checks': {'all_four_pinned_key_signatures_verified': True,
                             'fresh_original_release_and_startup_correspondence': True,
                             'complete_plan_and_signature_sources_reobserved': True},
                  'authority': {'trust_policy_owner_or_signers_authenticated': False,
                                'source_or_build_provenance_authenticated': False, 'nested_secrets_authenticated': False,
                                'clock_or_sequence_floor_authenticated': False, 'rollback_floor_persisted': False,
                                'application_executed': False, 'native_runtime_authenticated': False,
                                'published': False, 'installed': False, 'network_or_gpu_changed': False,
                                'server_ready': False},
                  'limits': ['The explicit caller policy hash selects four key pins and sequence floors. No authority to choose those pins, revocation status, authenticated time or persistent monotonic floor is inferred.',
                             'Signatures cover each exact release manifest, which binds complete payloads and the original top-level startup hashes. Fresh shipped policy observes nested credentials, but those nested bytes are not automatically covered by the release signature.',
                             'Complete application, raw configuration and nested credential plans are rebuilt afterward. These are sequential observations, not atomicity, ABA or hostile same-UID protection.',
                             'Synthetic or actual developer inputs are not installed-root, authenticated Git/build/native-runtime, application behavior or target evidence. No signing, publication, installation, account, listener, manager or GPU operation is supplied.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'policy', 'policy-sha256', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--at', type=int)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.manifest, args.policy, args.policy_sha256, args.openssl_sha256, args.at)
        output = json.dumps(result, sort_keys=True, separators=(',', ':'))
        if len(output) > 1024 * 1024:
            raise ValueError('application attestation output bound')
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Private application attestation preflight refused', file=sys.stderr)
        return 75
    print(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())

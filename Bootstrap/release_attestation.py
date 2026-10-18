"""Verify a detached, scoped release attestation and every staged payload byte.

Trust comes from an explicit caller key pin, sequence floor and evaluation time.
This tool never signs, publishes, installs or executes an application release.
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
DOMAIN = b'azurelinux3s4 application-release attestation v1\n'
ED25519_SPKI = bytes.fromhex('302a300506032b6570032100')
FIELDS = {'schema', 'purpose', 'application', 'commit', 'tree', 'manifest_sha256',
          'key_sha256', 'sequence', 'not_before', 'not_after'}
MAX_VALIDITY = 31 * 86400


def module(name):
    spec = importlib.util.spec_from_file_location('release_attestation_' + name, ROOT/'Bootstrap'/(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


INPUTS = module('tls_inputs')
RELEASE = INPUTS.RELEASE


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate attestation field')
        result[key] = value
    return result


def constant(_):
    raise ValueError('nonfinite attestation value')


def envelope(raw, app, commit, tree, manifest_sha256, key_sha256, minimum_sequence, current):
    if (type(raw) is not bytes or not 0 < len(raw) <= 16384 or not raw.endswith(b'\n')
            or any(value != 10 and not 32 <= value <= 126 for value in raw)):
        raise ValueError('bounded canonical attestation bytes required')
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    if type(value) is not dict or value.keys() != FIELDS:
        raise ValueError('exact attestation fields required')
    expected = {'schema': 1, 'purpose': 'azurelinux3s4-application-release', 'application': app,
                'commit': commit, 'tree': tree, 'manifest_sha256': manifest_sha256, 'key_sha256': key_sha256}
    if any(type(value[name]) is not type(item) or value[name] != item for name, item in expected.items()):
        raise ValueError('attestation scope differs from explicit release or key')
    if (type(minimum_sequence) is not int or not 1 <= minimum_sequence < 2**63
            or type(current) is not int or not 946684800 <= current <= 4102444800
            or type(value['sequence']) is not int or not minimum_sequence <= value['sequence'] < 2**63
            or any(type(value[name]) is not int for name in ('not_before', 'not_after'))
            or not 946684800 <= value['not_before'] < value['not_after'] <= 4102444800
            or value['not_after'] - value['not_before'] > MAX_VALIDITY
            or not value['not_before'] <= current < value['not_after']):
        raise ValueError('attestation sequence or validity window refused')
    if (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii') != raw:
        raise ValueError('attestation must already use the canonical byte representation')
    return value


def audit(app, commit, tree, manifest_sha256, release, attestation, signature, public_key,
          public_key_sha256, openssl_sha256, minimum_sequence, at=None, expected_sources=None):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    if type(public_key_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', public_key_sha256):
        raise ValueError('explicit canonical public verification key pin required')
    current = int(time.time()) if at is None else at
    before = RELEASE.verify(app, commit, tree, manifest_sha256, release)
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack, RELEASE.absolute(release), links)
        contract = RELEASE.contracts(); inventory = RELEASE.inventory(root, contract)
        manifest, manifest_identity = RELEASE.read_file(root, 'release.json', contract['REL_MANIFEST_LIMIT'], capture=True)
        if manifest[1] != manifest_sha256:
            raise ValueError('original release manifest changed')
        captured = {name: INPUTS.private_input(stack, links, path) for name, path in
                    (('attestation', attestation), ('signature', signature), ('public_key', public_key))}
        commitments = {name: {'bytes': row[2][0], 'sha256': row[2][1]} for name, row in captured.items()}
        if expected_sources is not None and expected_sources != commitments:
            raise ValueError('attestation inputs differ from the complete preflight source commitments')
        raw = captured['attestation'][2][2]; key = captured['public_key'][2][2]; signed = captured['signature'][2][2]
        if (len(key) != len(ED25519_SPKI) + 32 or not key.startswith(ED25519_SPKI)
                or hashlib.sha256(key).hexdigest() != public_key_sha256 or len(signed) != 64):
            raise ValueError('pinned canonical Ed25519 SPKI and detached 64-byte signature required')
        selected = envelope(raw, app, commit, tree, manifest_sha256, public_key_sha256, minimum_sequence, current)
        native = INPUTS.NativeOpenSSL(stack, openssl_sha256)
        version = native.run(['version', '-v']).decode('ascii').strip()
        if native.last_stderr or not re.fullmatch(r'OpenSSL 3\.[0-9]+\.[0-9]+[^\r\n]{0,180}', version):
            raise ValueError('OpenSSL 3 development verifier required')
        message = DOMAIN + raw
        descriptors = {name: INPUTS.sealed_input(stack, 'attestation-' + name, content)
                       for name,content in (('key', key), ('signature', signed), ('message', message))}
        path = lambda name: '/proc/self/fd/' + str(descriptors[name])
        verified = native.run(['pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', path('key'),
                               '-rawin', '-sigfile', path('signature'), '-in', path('message')],
                              descriptors=tuple(descriptors.values()))
        if verified != b'Signature Verified Successfully\n' or native.last_stderr:
            raise ValueError('native release signature confirmation refused')
        after = RELEASE.verify(app, commit, tree, manifest_sha256, release)
        if after != before or RELEASE.inventory(root, contract) != inventory:
            raise ValueError('complete release changed during signature verification')
        fresh_manifest, _ = RELEASE.read_file(root, 'release.json', contract['REL_MANIFEST_LIMIT'],
                                              capture=True, expected=manifest_identity)
        if fresh_manifest != manifest:
            raise ValueError('release manifest changed during signature verification')
        for parent, leaf, original, identity in captured.values():
            again, _ = RELEASE.read_file(parent, leaf, INPUTS.INPUT_LIMIT, capture=True, expected=identity)
            if again != original: raise ValueError('original signature source changed')
        RELEASE.check_links(links); native.check()
        result = {'scope': 'PINNED-KEY DEVELOPMENT RELEASE ATTESTATION', 'application': app,
                  'declaration': before['declaration'], 'files': before['files'], 'payload_bytes': before['payload_bytes'],
                  'attestation': selected, 'evaluation_unix_seconds': current, 'explicit_time_supplied': at is not None,
                  'minimum_sequence': minimum_sequence, 'signed_message_bytes': len(message),
                  'source_commitments_supplied': expected_sources is not None,
                  'signed_message_sha256': hashlib.sha256(message).hexdigest(),
                  'sources': {name: {'bytes': row[2][0], 'sha256': row[2][1], 'identity': list(row[3])}
                              for name,row in captured.items()},
                  'openssl': {'path': INPUTS.OPENSSL, 'sha256': openssl_sha256, 'version': version,
                              'identity': list(RELEASE.identity(native.before)), 'commands': native.commands},
                  'checks': {'ed25519_signature_valid_for_pinned_key': True, 'exact_release_scope_bound': True,
                             'within_explicit_sequence_and_time_policy': True, 'complete_payloads_reobserved': True},
                  'authority': {'signer_identity_or_key_intent_authenticated': False, 'key_revocation_checked': False,
                                'clock_or_sequence_floor_authenticated': False, 'rollback_floor_persisted': False,
                                'source_commit_or_build_process_authenticated': False, 'vendor_runtime_authenticated': False,
                                'application_executed': False, 'signed_or_published': False, 'installed': False,
                                'network_or_gpu_changed': False, 'server_ready': False},
                  'limits': ['Signature verification binds this exact manifest commitment, app, source declarations, key, sequence and finite validity interval under an explicit caller key pin. It does not establish who owns that pin or whether its signer is currently authorized.',
                             'All complete staged payload hashes/modes and original manifest/attestation/signature/key bytes are reobserved. Source commit/tree strings and configuration hashes remain signed declarations, not proof of source checkout, build inputs, analyzer results or application behavior.',
                             'The caller supplies the minimum accepted sequence. No monotonic state, revocation list, clock authentication, threshold signature, transparency or rollback-floor update is implemented.',
                             'Native inputs are bounded sealed memory files and the executable is hash/identity checked. Trusted base/native dependencies, sequential non-atomic checks and ordinary deadlines do not prove hostile same-UID protection or hard progress.',
                             'Verification only: no signing key, signature creation, package adoption, publication, installation, app, service, network or GPU action is supplied.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'commit', 'tree', 'manifest-sha256', 'release', 'attestation', 'signature',
                 'public-key', 'public-key-sha256', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--minimum-sequence', type=int, required=True)
    parser.add_argument('--at', type=int)
    args = parser.parse_args(argv)
    try:
        result = audit(args.app, args.commit, args.tree, args.manifest_sha256, args.release, args.attestation,
                       args.signature, args.public_key, args.public_key_sha256, args.openssl_sha256,
                       args.minimum_sequence, args.at)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Release attestation verification refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

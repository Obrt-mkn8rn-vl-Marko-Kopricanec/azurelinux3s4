"""Compare an exact private SSH candidate with local sshd -G parser output.

This developer-only check starts no listener, loads no host keys and performs
no login. It neither reads the host sshd configuration nor installs a file.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PARSER = '/usr/sbin/sshd'
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'}
SAFE_DIRECTIVES = frozenset('''Port AddressFamily ListenAddress HostKey KexAlgorithms Ciphers MACs
HostKeyAlgorithms PubkeyAcceptedAlgorithms CASignatureAlgorithms RequiredRSASize FingerprintHash
RekeyLimit PermitRootLogin PubkeyAuthentication AuthenticationMethods PasswordAuthentication
KbdInteractiveAuthentication PermitEmptyPasswords HostbasedAuthentication GSSAPIAuthentication
UsePAM StrictModes UseDNS AuthorizedKeysFile RevokedKeys AuthorizedKeysCommand AuthorizedPrincipalsFile
AuthorizedPrincipalsCommand TrustedUserCAKeys AllowUsers PermitUserEnvironment PermitUserRC PermitTTY
DisableForwarding AllowTcpForwarding AllowStreamLocalForwarding AllowAgentForwarding X11Forwarding
PermitTunnel GatewayPorts PermitOpen PermitListen Compression LoginGraceTime MaxAuthTries MaxSessions
MaxStartups ClientAliveInterval ClientAliveCountMax ChannelTimeout LogLevel Subsystem'''.split())


def module(name, path):
    spec = importlib.util.spec_from_file_location('ssh_preflight_' + name, ROOT/path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PREFLIGHT = module('preflight', 'Bootstrap/preflight.py')
NATIVE = module('native', 'Bootstrap/native_tool.py')
POLICY = module('policy', 'SSH/policy.py')


def parser_input(candidate):
    admin = candidate['manifest']['admin']
    expected = POLICY.bundle([row['prefix'] for row in admin], [row['address'] for row in admin])
    row = expected['files'][0]
    if candidate['ssh_policy'] != expected or candidate['files'][0] != row:
        raise ValueError('complete current SSH policy and byte commitments required')
    raw = row['content'].encode('ascii')
    if (not 0 < len(raw) <= 65536 or not raw.endswith(b'\n') or len(raw) != row['bytes']
            or hashlib.sha256(raw).hexdigest() != row['sha256']
            or any(value != 10 and not 32 <= value <= 126 for value in raw)):
        raise ValueError('bounded canonical SSH configuration required')
    declarations = {}
    for line in raw.decode('ascii').splitlines():
        if line.startswith('#'):
            continue
        key, separator, value = line.partition(' ')
        if (not separator or key not in SAFE_DIRECTIVES or not value or value != value.strip()
                or any(character in value for character in ('\\', '"', "'", '#'))
                or '=' in value and key != 'ChannelTimeout'):
            raise ValueError('unsupported SSH parser-input syntax')
        values = declarations.setdefault(key.lower(), [])
        if values and key not in ('ListenAddress', 'HostKey'):
            raise ValueError('unexpected duplicate SSH directive')
        values.append(value)
    if declarations.keys() != {key.lower() for key in SAFE_DIRECTIVES}:
        raise ValueError('complete explicit SSH directive set required')
    # These are the selected profile's documented native presentation changes,
    # not an arbitrary OpenSSH grammar, unit converter or input normalizer.
    if declarations['rekeylimit'] != ['256M 1h'] or declarations['fingerprinthash'] != ['sha256']:
        raise ValueError('unsupported SSH native presentation profile')
    declarations['rekeylimit'] = ['268435456 3600']
    declarations['fingerprinthash'] = ['SHA256']
    declarations['allowusers'] = declarations['allowusers'][0].split(' ')
    declarations['listenaddress'] = sorted('[' + address + ']:22' if ipaddress.ip_address(address).version == 6
                                          else address + ':22' for address in declarations['listenaddress'])
    return raw, declarations


def reconcile(raw, expected):
    if (type(raw) is not bytes or not 0 < len(raw) <= NATIVE.OUTPUT_LIMIT or not raw.endswith(b'\n')
            or any(value != 10 and not 32 <= value <= 126 for value in raw)):
        raise ValueError('bounded native SSH configuration output required')
    observed = {}
    for line in raw.decode('ascii').splitlines():
        key, separator, value = line.partition(' ')
        if (not re.fullmatch('[a-z][a-z0-9]*', key) or not separator or not value or value != value.strip()):
            raise ValueError('unsupported native SSH configuration output')
        observed.setdefault(key, []).append(value)
    for key, values in expected.items():
        actual = observed.get(key)
        if key == 'listenaddress' and actual is not None:
            actual = sorted(actual)
        if actual != values:
            raise ValueError('native SSH setting differs: ' + key)
    return observed


def audit(private_root, manifest, parser_sha256):
    if os.geteuid() == 0:
        raise ValueError('unprivileged developer required')
    before = PREFLIGHT.preflight(private_root, manifest, kind='deployment', include_candidate=True)
    raw, expected = parser_input(before['candidate'])
    with contextlib.ExitStack() as stack:
        native = NATIVE.PinnedExecutable(stack, parser_sha256, path=PARSER, label='sshd',
                                        environment=ENVIRONMENT, timeout=10)
        version_stdout = native.run(['-V'])
        version = native.last_stderr.decode('ascii')
        match = re.fullmatch(r'OpenSSH_(\d+)\.(\d+)p\d+(?:, | )[ -~]+\n', version)
        if version_stdout or not match or not (9, 3) <= tuple(map(int, match.groups())) <= (10, 0):
            raise ValueError('selected OpenSSH 9.3 through 10.0 development parser required')
        # OpenSSH closes inherited descriptors before reading configuration.
        # Supply the admitted bytes on stdin, never a host config or Include.
        dump = native.run(['-G', '-e', '-f', '/dev/stdin'], raw)
        if native.last_stderr:
            raise ValueError('native SSH parser emitted diagnostics')
        observed = reconcile(dump, expected)
        if PREFLIGHT.preflight(private_root, manifest, kind='deployment', include_candidate=True) != before:
            raise ValueError('deployment plan changed during native SSH parsing')
        native.check()
        result = {'scope': 'PRIVATE DEVELOPMENT SSH CONFIGURATION PARSING',
                  'software_sha256': before['software_sha256'], 'manifest_sha256': before['manifest_sha256'],
                  'publication_sha256': before['publication_sha256'],
                  'configuration': {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
                  'parser': {'path': PARSER, 'sha256': parser_sha256, 'version': version,
                             'identity': list(NATIVE.RELEASE.identity(native.before)), 'commands': native.commands},
                  'matched_directives': expected, 'native_output': {'bytes': len(dump),
                      'sha256': hashlib.sha256(dump).hexdigest(), 'content': dump.decode('ascii'), 'settings': observed},
                  'checks': {'exact_current_configuration': True, 'all_explicit_native_settings_match': True,
                             'no_parser_diagnostics': True, 'full_source_plan_reobserved': True},
                  'authority': {'vendor_and_dependencies_authenticated': False, 'target_parser_passed': False,
                                'native_defaults_approved': False, 'account_or_key_usability_proven': False,
                                'pam_or_authentication_executed': False, 'provider_or_handshake_proven': False,
                                'listener_or_original_client_origin_proven': False, 'published_or_installed': False,
                                'network_or_gpu_changed': False, 'server_ready': False},
                  'limits': ['Only the exact standalone candidate and caller-pinned local sshd -G parser are checked. No Include, Match, command override, listener, login or key-loading mode is supplied.',
                             'Every explicit directive must match; extra compiled defaults are reported without approval. Listener order alone is irrelevant; multiplicity, addresses and ports remain exact.',
                             'The fixed executable hash is not installed-vendor, shared-library, provider, key, account, PAM or target authentication. Source checks remain sequential and ordinary deadlines are not hard blocked-IO guarantees.',
                             'No installed file, daemon invocation, effective target environment, firewall/origin enforcement, boot recovery or actual SSH session is proven.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'manifest', 'parser-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.manifest, args.parser_sha256)
        output = json.dumps(result, sort_keys=True, separators=(',', ':'))
        if len(output) > 4 * NATIVE.OUTPUT_LIMIT:
            raise ValueError('SSH check output bound')
    except (OSError, ValueError, TypeError, AttributeError, KeyError, MemoryError, RecursionError,
            OverflowError, UnicodeError, subprocess.SubprocessError):
        print('Private SSH configuration check refused', file=sys.stderr)
        return 75
    print(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())

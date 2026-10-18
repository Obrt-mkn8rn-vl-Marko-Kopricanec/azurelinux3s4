"""Check explicit private TLS inputs with a pinned local OpenSSL 3 executable.

This developer command performs offline cryptographic checks only. It neither
contacts a server nor installs certificates, keys, trust anchors or services.
"""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


SPEC = importlib.util.spec_from_file_location('tls_release_inputs', Path(__file__).with_name('release.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
OPENSSL = '/usr/bin/openssl'
INPUT_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 1024 * 1024
COMMAND_SECONDS = 10
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'}
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL


def pem_blocks(raw, labels, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= INPUT_LIMIT:
        raise ValueError('bounded complete PEM input required')
    pattern = re.compile(rb'-----BEGIN ([A-Z ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END \1-----\r?\n')
    result, cursor = [], 0
    for found in pattern.finditer(raw):
        if found.start() != cursor or found[1].decode('ascii') not in labels or len(result) >= maximum:
            raise ValueError('complete explicit PEM blocks required')
        lines = found[2].splitlines()
        if not lines or any(not 1 <= len(line) <= 64 for line in lines):
            raise ValueError('bounded PEM base64 lines required')
        encoded = b''.join(lines)
        decoded = base64.b64decode(encoded, validate=True)
        if not decoded or base64.b64encode(decoded) != encoded:
            raise ValueError('canonical PEM base64 required')
        result.append(decoded); cursor = found.end()
    if not result or cursor != len(raw):
        raise ValueError('unsupported or trailing PEM data')
    return result


def sealed_input(stack, label, raw):
    fd = os.memfd_create('tls-input-' + label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    stack.callback(os.close, fd)
    RELEASE.write_all(fd, raw)
    os.lseek(fd, 0, os.SEEK_SET)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS != SEALS:
        raise ValueError('complete native input seals required')
    if os.fstat(fd).st_size != len(raw) or os.read(fd, len(raw) + 1) != raw:
        raise ValueError('sealed native input readback mismatch')
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def private_input(stack, links, path):
    path = Path(RELEASE.absolute(path))
    parent = RELEASE.anchor(stack, str(path.parent), links)
    info = os.fstat(parent)
    if (info.st_uid != os.geteuid() or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('private developer-owned 0700 input parent required')
    raw, identity = RELEASE.read_file(parent, path.name, INPUT_LIMIT, capture=True)
    if identity[4] != os.getegid() or stat.S_IMODE(identity[2]) != 0o600:
        raise ValueError('private developer-owned 0600 TLS input required')
    return parent, path.name, raw, identity


class NativeOpenSSL:
    def __init__(self, stack, expected):
        if type(expected) is not str or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('explicit expected OpenSSL SHA256 required')
        self.links = []
        self.parent = RELEASE.anchor(stack, '/usr/bin', self.links)
        self.fd = os.open('openssl', RELEASE.READ, dir_fd=self.parent)
        stack.callback(os.close, self.fd)
        self.before = os.fstat(self.fd)
        if (not stat.S_ISREG(self.before.st_mode) or self.before.st_uid != 0
                or self.before.st_nlink != 1 or self.before.st_mode & 0o7022
                or not self.before.st_mode & 0o111 or not 0 < self.before.st_size <= 32 * 1024 * 1024):
            raise ValueError('bounded protected root-owned OpenSSL executable required')
        self.expected, self.commands = expected, []
        self.check()

    def check(self):
        for _ in range(2):
            os.lseek(self.fd, 0, os.SEEK_SET)
            digest, size = hashlib.sha256(), 0
            while True:
                raw = os.read(self.fd, min(128 * 1024, self.before.st_size + 1 - size))
                if not raw: break
                size += len(raw); digest.update(raw)
                if size > self.before.st_size: raise ValueError('OpenSSL executable changed size')
            if size != self.before.st_size or digest.hexdigest() != self.expected:
                raise ValueError('OpenSSL executable pin mismatch')
        for current in (os.fstat(self.fd), os.stat('openssl', dir_fd=self.parent, follow_symlinks=False)):
            if RELEASE.identity(current) != RELEASE.identity(self.before):
                raise ValueError('OpenSSL executable identity changed')
        RELEASE.check_links(self.links)

    def run(self, arguments, raw=b'', descriptors=()):
        # Only fixed calls below use this method. Neither input paths, arbitrary
        # options, provider plugins nor a caller-selected command are admitted.
        self.check()
        start = time.monotonic()
        child = subprocess.run([OPENSSL, *arguments], executable='/proc/self/fd/' + str(self.fd),
                               pass_fds=(self.fd, *descriptors), input=raw, capture_output=True,
                               env=ENVIRONMENT, cwd='/', timeout=COMMAND_SECONDS, check=False)
        self.commands.append({'arguments': list(arguments), 'actual_returncode': child.returncode,
                              'elapsed_seconds': time.monotonic() - start,
                              'stdout_bytes': len(child.stdout), 'stderr_bytes': len(child.stderr),
                              'stdout_sha256': hashlib.sha256(child.stdout).hexdigest(),
                              'stderr_sha256': hashlib.sha256(child.stderr).hexdigest()})
        if (child.returncode != 0 or len(child.stdout) > OUTPUT_LIMIT or len(child.stderr) > OUTPUT_LIMIT):
            raise ValueError('local OpenSSL check refused')
        self.check()
        return child.stdout


def dns_names(raw, contract):
    matched = re.fullmatch(rb'X509v3 Subject Alternative Name:(?: critical)? ?\n    ([A-Za-z0-9:., -]+)\n', raw)
    if matched is None:
        raise ValueError('explicit canonical DNS subject alternative names required')
    entries = matched[1].decode('ascii').split(', ')
    if not 1 <= len(entries) <= 128 or len(set(entries)) != len(entries):
        raise ValueError('bounded unique DNS subject alternative names required')
    names = []
    for entry in entries:
        if not entry.startswith('DNS:'):
            raise ValueError('only explicit DNS SAN entries supported')
        names.append(contract['deployment_domain'](entry[4:]))
    return names


def audit(domain, certificate, key, anchors, openssl_sha256, intermediates=None, at=None, minimum_seconds=86400,
          expected_sources=None):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    contract = RELEASE.contracts()
    contract['deployment_domain'](domain)
    current = int(time.time()) if at is None else at
    if (type(current) is not int or not 946684800 <= current <= 4102444800
            or type(minimum_seconds) is not int or not 0 <= minimum_seconds <= 366 * 86400):
        raise ValueError('bounded evaluation time and validity margin required')
    paths = {'certificate': certificate, 'key': key, 'anchors': anchors}
    if intermediates is not None: paths['intermediates'] = intermediates
    with contextlib.ExitStack() as stack:
        links = []
        captured = {name: private_input(stack, links, path) for name, path in paths.items()}
        inputs = {name: row[2][2] for name, row in captured.items()}
        if expected_sources is not None:
            if type(expected_sources) is not dict or expected_sources.keys() != paths.keys():
                raise ValueError('complete expected TLS source commitments required')
            for name, expected in expected_sources.items():
                if (type(expected) is not dict or expected.keys() != {'bytes', 'sha256'}
                        or type(expected['bytes']) is not int or not 0 < expected['bytes'] <= INPUT_LIMIT
                        or type(expected['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', expected['sha256'])
                        or (expected['bytes'], expected['sha256']) != captured[name][2][:2]):
                    raise ValueError('TLS input differs from expected source commitment')
        leaf = pem_blocks(inputs['certificate'], {'CERTIFICATE'}, 1)[0]
        pem_blocks(inputs['key'], {'PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY'}, 1)
        anchor_count = len(pem_blocks(inputs['anchors'], {'CERTIFICATE'}, 64))
        intermediate_count = (len(pem_blocks(inputs['intermediates'], {'CERTIFICATE'}, 16))
                              if intermediates is not None else 0)
        native = NativeOpenSSL(stack, openssl_sha256)
        version = native.run(['version', '-v']).decode('ascii').strip()
        if not re.fullmatch(r'OpenSSL 3\.[0-9]+\.[0-9]+[^\r\n]{0,180}', version):
            raise ValueError('explicit supported OpenSSL 3 version required')
        native.run(['pkey', '-inform', 'PEM', '-passin', 'pass:', '-check', '-noout'], inputs['key'])
        private_public = native.run(['pkey', '-inform', 'PEM', '-passin', 'pass:', '-pubout', '-outform', 'DER'], inputs['key'])
        certificate_public = pem_blocks(native.run(['x509', '-inform', 'PEM', '-pubkey', '-noout'],
                                                   inputs['certificate']), {'PUBLIC KEY'}, 1)[0]
        if private_public != certificate_public:
            raise ValueError('TLS certificate and private key public components differ')
        names = dns_names(native.run(['x509', '-inform', 'PEM', '-noout', '-ext', 'subjectAltName'],
                                     inputs['certificate']), contract)
        if domain not in names:
            raise ValueError('declared hostname absent from exact DNS SAN entries')
        trusted = sealed_input(stack, 'anchors', inputs['anchors'])
        arguments = ['verify', '-no-CAfile', '-no-CApath', '-no-CAstore', '-trusted', '/proc/self/fd/' + str(trusted),
                     '-purpose', 'sslserver', '-verify_hostname', domain, '-auth_level', '2',
                     '-verify_depth', '8', '-x509_strict', '-check_ss_sig']
        descriptors = [trusted]
        if intermediates is not None:
            fd = sealed_input(stack, 'intermediates', inputs['intermediates'])
            descriptors.append(fd); arguments.extend(('-untrusted', '/proc/self/fd/' + str(fd)))
        for instant in dict.fromkeys((current, current + minimum_seconds)):
            native.run([*arguments, '-attime', str(instant)], inputs['certificate'], tuple(descriptors))
        for name, (parent, filename, original, identity) in captured.items():
            after, _ = RELEASE.read_file(parent, filename, INPUT_LIMIT, capture=True, expected=identity)
            if after != original:
                raise ValueError('TLS original input changed during checks')
        RELEASE.check_links(links); native.check()
        result = {'scope': 'LOCAL DEVELOPMENT TLS INPUT CHECK', 'domain': domain,
                  'source_commitments_supplied': expected_sources is not None,
                  'evaluation_unix_seconds': current, 'explicit_time_supplied': at is not None,
                  'minimum_validity_seconds': minimum_seconds, 'dns_subject_alternative_names': names,
                  'certificate_der_sha256': hashlib.sha256(leaf).hexdigest(),
                  'public_key_der_sha256': hashlib.sha256(private_public).hexdigest(),
                  'anchor_certificates': anchor_count, 'intermediate_certificates': intermediate_count,
                  'sources': {name: {'bytes': row[2][0], 'sha256': row[2][1], 'identity': list(row[3])}
                              for name, row in captured.items()},
                  'openssl': {'path': OPENSSL, 'sha256': openssl_sha256, 'version': version,
                              'identity': list(RELEASE.identity(native.before)), 'commands': native.commands},
                  'checks': {'private_key_consistency': True, 'certificate_key_match': True,
                             'exact_dns_san': True, 'explicit_trust_chain_at_both_instants': True},
                  'authority': {'vendor_and_native_dependencies_authenticated': False,
                                'trust_anchor_intent_authenticated': False, 'clock_authenticated': False,
                                'revocation_or_ct_checked': False, 'actual_application_loaded_inputs': False,
                                'tls_handshake_proven': False, 'certificate_installed': False,
                                'network_or_gpu_changed': False, 'server_ready': False},
                  'limits': ['Pinned local executable and honest trusted OS/native dependencies; SHA matching is not vendor or provider authentication.',
                             'Only explicit roots/intermediates are used; no default CA store, CRL/OCSP/AIA download, system trust change or network command is supplied.',
                             'Exact DNS-only SAN subset; no wildcard, IP SAN or CN fallback. Clear PEM private keys only; no passphrase or hardware-provider adoption.',
                             'Two evaluated time points and an explicit trust set are not current-time authentication, revocation/CT evidence, a network handshake or application credential loading.',
                             'Original files are reobserved sequentially. Memory copies/sealed trust inputs do not give hostile same-UID secrecy, physical zeroization, atomic source snapshots or future custody.',
                             'Timeouts bound ordinary subprocess waits, not hard native blocked-IO progress. No installation, account, service, DNS or GPU action occurs.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('domain', 'certificate', 'key', 'anchors', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--intermediates')
    parser.add_argument('--at', type=int, help='optional explicit Unix evaluation time, recorded as supplied')
    parser.add_argument('--minimum-seconds', type=int, default=86400)
    args = parser.parse_args(argv)
    try:
        result = audit(args.domain, args.certificate, args.key, args.anchors, args.openssl_sha256,
                       args.intermediates, args.at, args.minimum_seconds)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, MemoryError, RecursionError,
            OverflowError, subprocess.SubprocessError):
        print('Local TLS input check refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Inspect public-key snapshots; emit prospective entries without granting access."""

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import struct
import subprocess
import sys
import tempfile


SOURCE_LIMIT = 1024 * 1024
LINE_LIMIT = 8192
KEY_LIMIT = 64
BLOB_LIMIT = 2048
KEYGEN = '/usr/bin/ssh-keygen'
COMMENT = 'azurelinux3s4-candidate'


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def snapshot(path):
    before = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_mode & 0o022 or not 0 < before.st_size <= SOURCE_LIMIT):
        raise ValueError('source must be a bounded protected regular file owned by the inspecting user')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(descriptor)) != identity(before):
            raise ValueError('source identity changed before snapshot')
        pieces, size = [], 0
        while True:
            piece = os.read(descriptor, min(65536, SOURCE_LIMIT + 1 - size))
            if not piece:
                break
            pieces.append(piece)
            size += len(piece)
            if size > SOURCE_LIMIT:
                raise ValueError('source exceeds snapshot bound')
        if (size != before.st_size or identity(os.fstat(descriptor)) != identity(before)
                or identity(os.stat(path, follow_symlinks=False)) != identity(before)):
            raise ValueError('source changed during snapshot')
        return b''.join(pieces)
    finally:
        os.close(descriptor)


def wire_fields(blob, count):
    offset, fields = 0, []
    for _ in range(count):
        if len(blob) - offset < 4:
            raise ValueError('truncated public-key wire length')
        size = struct.unpack_from('>I', blob, offset)[0]
        offset += 4
        if not 0 < size <= BLOB_LIMIT or size > len(blob) - offset:
            raise ValueError('unsupported public-key wire field')
        fields.append(blob[offset:offset + size])
        offset += size
    if offset != len(blob):
        raise ValueError('public-key wire has trailing data')
    return fields


def positive_mpint(value):
    if value[0] & 0x80 or (value[0] == 0 and (len(value) < 2 or not value[1] & 0x80)):
        raise ValueError('RSA integer is not canonical positive SSH mpint')
    return int.from_bytes(value, 'big')


def parse(data):
    if (not 0 < len(data) <= SOURCE_LIMIT or not data.endswith(b'\n')
            or any(value > 126 or value < 32 and value not in (9, 10) for value in data)):
        raise ValueError('public-key source must use bounded ASCII lines with a final LF')
    keys, seen = [], set()
    lines = data.split(b'\n')
    if len(lines) > 4096:
        raise ValueError('too many public-key source lines')
    for line in lines:
        if len(line) > LINE_LIMIT:
            raise ValueError('public-key source line exceeds bound')
        line = line.strip(b' \t')
        if not line or line.startswith(b'#'):
            continue
        pieces = line.split(None, 2)
        if len(pieces) < 2 or pieces[0] not in (b'ssh-ed25519', b'ssh-rsa'):
            raise ValueError('only bare supported public keys are accepted; source options are refused')
        if len(pieces[1]) > 4 * ((BLOB_LIMIT + 2) // 3):
            raise ValueError('public-key encoding exceeds bound')
        try:
            blob = base64.b64decode(pieces[1], validate=True)
        except binascii.Error as error:
            raise ValueError('invalid public-key base64') from error
        if not 0 < len(blob) <= BLOB_LIMIT or base64.b64encode(blob) != pieces[1]:
            raise ValueError('noncanonical public-key base64')
        kind = pieces[0].decode('ascii')
        fields = wire_fields(blob, 2 if kind == 'ssh-ed25519' else 3)
        if fields[0] != pieces[0]:
            raise ValueError('text and wire public-key types differ')
        if kind == 'ssh-ed25519':
            if len(fields[1]) != 32:
                raise ValueError('Ed25519 public-key field must be exactly 32 bytes')
            bits, native_kind = 256, 'ED25519'
        else:
            exponent, modulus = (positive_mpint(value) for value in fields[1:])
            bits, native_kind = modulus.bit_length(), 'RSA'
            if exponent != 65537 or not 3072 <= bits <= 8192 or not modulus & 1:
                raise ValueError('RSA key does not satisfy the bounded candidate parameter policy')
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        if fingerprint in seen or len(keys) >= KEY_LIMIT:
            raise ValueError('duplicate or excessive public keys')
        seen.add(fingerprint)
        keys.append({'type': kind, 'bits': bits, 'fingerprint': fingerprint, 'native_kind': native_kind,
                     'entry': 'restrict,pty ' + kind + ' ' + pieces[1].decode('ascii') + ' ' + COMMENT + '\n'})
    if not keys:
        raise ValueError('no supported public keys')
    return keys


def bounded_output(path, limit):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('native fingerprint output exceeds bound')
    return data


def native_fingerprints(content, keys):
    # ssh-keygen only lists PUBLIC fingerprints. It never signs, authenticates,
    # generates a production private key or installs an authorized_keys file.
    with tempfile.TemporaryDirectory(prefix='s4-ssh-key-inspection-') as directory:
        base = Path(directory)
        candidate, output, errors = (base / name for name in ('candidate.pub', 'stdout', 'stderr'))
        with candidate.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
        candidate_identity = identity(candidate.stat())
        with output.open('xb') as stdout, errors.open('xb') as stderr:
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
            result = subprocess.run([KEYGEN, '-l', '-f', str(candidate), '-E', 'sha256'],
                                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=10, check=False)
        actual, diagnostics = bounded_output(output, 16384), bounded_output(errors, 8192)
        expected = ''.join(str(key['bits']) + ' ' + key['fingerprint'] + ' ' + COMMENT
                           + ' (' + key['native_kind'] + ')\n' for key in keys).encode('ascii')
        if (result.returncode != 0 or diagnostics or actual != expected
                or snapshot(candidate) != content or identity(candidate.stat()) != candidate_identity):
            raise ValueError('native fingerprint records do not match the complete public-key snapshot')
    # Normal temporary-directory cleanup is part of success, not best effort.


def inspect(path):
    data = snapshot(path)
    keys = parse(data)
    content = ''.join(key['entry'] for key in keys).encode('ascii')
    native_fingerprints(content, keys)
    return {
        'scope': 'PUBLIC-KEY SNAPSHOT / NATIVE FINGERPRINT OBSERVATION ONLY',
        'source_bytes': len(data), 'source_sha256': hashlib.sha256(data).hexdigest(),
        'keys': [{name: key[name] for name in ('type', 'bits', 'fingerprint')} for key in keys],
        'candidate': {'file': 'ssh/admin_authorized_keys', 'mode': '0600', 'bytes': len(content),
                      'sha256': hashlib.sha256(content).hexdigest(), 'content': content.decode('ascii')},
        'authority': {name: False for name in (
            'administrator_credential_authorized', 'owner_authority_verified', 'private_key_possession_proven',
            'cryptographic_validity_proven', 'signature_algorithm_policy_proven', 'native_azure_policy_proven',
            'trusted_source_ancestry_proven', 'root_managed_destination_proven', 'local_origin_proven',
            'ssh_authentication_executed', 'accounts_created', 'keys_provisioned', 'installation_authorized',
            'services_activated', 'server_ready')},
        'limits': [
            'Inspecting-user ownership and sequential leaf identity checks do not establish credential authority, '
            'protected parent ancestry, atomicity, ABA or concurrent-root protection.',
            'Wire format, chosen RSA parameters and native fingerprints do not prove Ed25519 point validity, '
            'RSA prime generation, private-key possession, signature authentication or target crypto/FIPS policy.',
            'ssh-rsa is the RSA public-key blob type; RSA SHA-2 signature policy is a separate prerequisite.',
            'Prospective restrict,pty entries allow a terminal while retaining key-option forwarding/userRC restrictions; '
            'they are not installed or authorized. A permitted shell can run another forwarder.',
            'No source discovery, account/key generation, credential handoff, configuration or host mutation. '
            'Future installation must authorize and consume these SAME candidate bytes under checked destination policy.',
            'Trusted base/OpenSSH/Python/procfs/private temporary ancestry and finite honest IO/scheduling remain assumptions. '
            'No native Azure, login, LAN-origin, boot/recovery or full-server readiness proof.'
        ],
    }


def main():
    if len(sys.argv) != 2:
        return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = inspect(sys.argv[1])
    except (OSError, ValueError, subprocess.SubprocessError):
        # Never echo source data: a mistaken private/secret input must not leak.
        print('SSH public-key inspection refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())

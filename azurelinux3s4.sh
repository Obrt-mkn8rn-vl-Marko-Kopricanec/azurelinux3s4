#!/bin/bash
# Azure Linux 3 Safe SSH Server Set-up. This checkpoint is a bootstrap foundation.
# Full host/network/SSH/web/runtime hardening is deliberately not reported ready.

set -Eeuo pipefail

S4_VERSION=0.6.0
S4_OS_RELEASE=/etc/os-release
S4_SYSTEMD_RUNTIME=/run/systemd/system
S4_STATE=/var/lib/azurelinux3s4
S4_RUN=/run/azurelinux3s4
S4_INSTALL_DIR=/usr/local/lib/azurelinux3s4
S4_SYSTEMD_DIR=/etc/systemd/system
S4_GPG_KEY=$S4_STATE/vendor-rpm-key.asc
# Azure Linux 3's vendor source key, independently checked against signed
# production base/extended metadata. Rotation requires newly vetted pins.
S4_VENDOR_KEY_SHA256=1092f37ec429e58bf9c7f898df17c3c32eb2ce3c4c037afb8ffe2d2b42e16e89
S4_VENDOR_FINGERPRINT=2BC94FFF7015A5F28F1537AD0CD9FED33135CE90
S4_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.trust.crt
S4_PLUGIN_CONFIG=/etc/tdnf/pluginconf.d/tdnfrepogpgcheck.conf
S4_PLUGIN_LIBRARY=/usr/lib64/tdnf-plugins/libtdnfrepogpgcheck.so
S4_REPAIR_TIMER=azurelinux3s4-repair.timer
S4_RECOVERY_TIMER=azurelinux3s4-finalization-recovery.timer
S4_COMPONENTS=(trust-anchor bootstrap repository-trust update-preparation update-compatibility)
S4_UPDATE_TIMER=azurelinux3s4-update-preparation.timer
# Internal dynamic-scope options; never accept inherited environment values.
S4_ADMISSION_DESTINATION=
S4_DOWNLOAD_DIRECTORY=
S4_BOOTSTRAP_PACKAGES=(ca-certificates curl openssl python3 gnupg2 tdnf-plugin-repogpgcheck)
S4_ARCH=
S4_NOW=

s4_log() {
    printf 'azurelinux3s4: %s\n' "$*" >&2
}

s4_os_value() {
    # Treat os-release as data, never as executable shell input.
    local key=$1
    awk -F= -v key="$key" '$1 == key {
        value = substr($0, length(key) + 2)
        if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
            value = substr(value, 2, length(value) - 2)
        }
        print value
        exit
    }' "$S4_OS_RELEASE"
}

s4_platform() {
    [[ -f $S4_OS_RELEASE ]] || { s4_log 'Cannot identify the operating system.'; return 78; }
    [[ $(s4_os_value ID) == azurelinux && $(s4_os_value VERSION_ID) == 3.0 ]] || {
        s4_log 'This installer supports Microsoft Azure Linux 3.0 only.'
        return 78
    }
    S4_ARCH=$(uname -m)
    case $S4_ARCH in
        x86_64|aarch64) ;;
        *) s4_log "Unsupported architecture: $S4_ARCH"; return 78 ;;
    esac
    [[ -d $S4_SYSTEMD_RUNTIME ]] || {
        s4_log 'A booted systemd host is required; a container filesystem is insufficient.'
        return 78
    }
}

s4_preflight() {
    [[ $EUID == 0 ]] || { s4_log 'Run with administrator privileges (sudo or root).'; return 77; }
    s4_platform || return $?
    local tool
    for tool in awk base64 bash cat chmod cmp date dirname flock head install mktemp mv rpm \
                ln readlink rm sha256sum stat sync systemctl tdnf timeout uname; do
        command -v "$tool" >/dev/null || {
            s4_log "The base image lacks required bootstrap command: $tool"
            return 78
        }
    done
}

s4_safe_path() {
    # A privileged write must not traverse a symlink or an untrusted directory.
    local path=$1 current mode owner
    [[ $path == /* && $path != *'/../'* && $path != */.. ]] || return 78
    current=$path
    while [[ $current != / ]]; do
        [[ ! -L $current ]] || { s4_log "Refusing symlink: $current"; return 78; }
        if [[ -e $current ]]; then
            owner=$(stat -c %u -- "$current") || return 78
            mode=$(stat -c %a -- "$current") || return 78
            if [[ $owner != 0 && $owner != "$EUID" ]] || (( (8#$mode & 0022) != 0 )); then
                s4_log "Refusing untrusted writable path: $current"
                return 78
            fi
        fi
        current=$(dirname -- "$current")
    done
}

s4_directory() {
    local path=$1 mode=$2
    s4_safe_path "$path" || return $?
    [[ ! -e $path || -d $path ]] || return 78
    install -d -m "$mode" -- "$path"
}

s4_atomic_write() {
    local path=$1 mode=$2 temporary
    s4_safe_path "$path" || return $?
    [[ ! -e $path || -f $path ]] || return 78
    temporary=$(mktemp "${path}.XXXXXX") || return $?
    if ! cat >"$temporary" || ! chmod "$mode" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if [[ -f $path ]] && cmp -s -- "$temporary" "$path"; then
        rm -f -- "$temporary"
        chmod "$mode" "$path" || return $?
        # A previous rename may be visible despite a failed persistence barrier.
        # Matching content must satisfy the same barrier as a new publication.
        sync "$path" || return $?
    else
        if ! sync "$temporary" || ! mv -fT -- "$temporary" "$path"; then
            rm -f -- "$temporary"
            return 1
        fi
    fi
    timeout --kill-after=5s 30s sync -f -- "$(dirname -- "$path")"
}

s4_prepare_state() {
    s4_directory "$S4_STATE" 0700 || return $?
    s4_directory "$S4_STATE/components" 0700 || return $?
    s4_directory "$S4_STATE/repos" 0700 || return $?
    s4_directory "$S4_RUN" 0700 || return $?
}

s4_lock_object() {
    local path=$1
    s4_safe_path "$path" || return $?
    # Opening a FIFO for writing can block before nonblocking flock is reached.
    # The private ancestry prevents an unprivileged replacement after this check.
    [[ ! -e $path || -f $path ]] || {
        s4_log "Refusing non-regular lock object: $path"
        return 78
    }
}

s4_lock() {
    local path=$S4_RUN/operation.lock descriptor=/proc/$$/fd/9 identity
    s4_lock_object "$path" || return $?
    # The component child inherits descriptor 9 and the same open-file lock.
    # A separately invoked component must acquire the lock itself.
    if [[ ! -e $descriptor ]] || [[ $(readlink "$descriptor") != "$path" ]]; then
        exec 9>>"$path" || return $?
    fi
    [[ -f $descriptor ]] || return 78
    identity=$(stat -Lc '%d:%i' -- "$descriptor") || return 78
    [[ $identity == "$(stat -c '%d:%i' -- "$path")" ]] || return 78
    if ! flock -n 9; then
        s4_log 'Another setup or repair is running; a later timer run will retry.'
        return 75
    fi
}

s4_state_value() {
    local component=$1 field=$2 value=0
    if [[ -f $S4_STATE/components/$component ]]; then
        value=$(awk -F= -v field="$field" '$1 == field { print $2; exit }' \
            "$S4_STATE/components/$component")
    fi
    # State is parsed, never sourced. Corruption resets bounded integer fields.
    [[ $value =~ ^[0-9]{1,10}$ ]] || value=0
    printf '%s\n' "$((10#$value))"
}

s4_write_state() {
    local component=$1 status=$2 attempts=$3 next=$4 result=$5
    s4_atomic_write "$S4_STATE/components/$component" 0600 <<EOF
version=$S4_VERSION
status=$status
attempts=$attempts
next_attempt=$next
last_exit=$result
last_attempt=$S4_NOW
EOF
}

s4_vendor_key_material() {
    # Public release key carried by this single executable; no network or GnuPG
    # prerequisite is needed to recover its vetted bytes. Never trust a new key
    # merely because a remote endpoint offers it.
    cat <<'S4_VENDOR_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BSN Pgp v1.1.0.0

mQENBF5v2nQBCADD+o8FgJQUcV9QTgdOTrYo8VtwHNOtTI1WWki8cUx+pI+aarHo
zYN3/QQj+a5lALWeWM/w+aT1q/xGBBkmr9Qo5xWaXeiKZaMVv3H+1HIOjVvrWOHX
zm+FvONB2fwAOclq9p7YaMqWtn4GckxD2YXhkTW0Y4kM+TcMTgSCiGKskjnmTfHw
G+SI9av/CZvqqfNZkdIuNTS9eSqTTenCKkgLvYRKSpkhZj1OuB/iTu+xK0BuoVns
jmju/Fw+tBrcdu3Q1sRXDrh8lnZgHxQUxHjwnyMlTM8a9N2qCgnu+SQjNyk3NXgi
dGSFkdtaF/Z+KNwG10XVs1jzjO/rtsrvrwJvABEBAAG0Ok1hcmluZXIgUlBNIFJl
bGVhc2UgU2lnbmluZyA8bWFyaW5lcnJwbXByb2RAbWljcm9zb2Z0LmNvbT6JATgE
EwEIACIFAl5v2nQCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEAzZ/tMx
Nc6QfaMH/iqp4Uyd66rAC2tSILWrH6RLkf05TIE0GZheqQkEO7a/Khy3u/Ej/HgC
QUlIC7yrJJGfNCyAx44Z/QsnrWz5EqVZOvjgY9MDpmzfve7KqmbnDBjmbSc6g8IH
HcgUYyfTHEUj69IfgNyJK4Io1vi1WgY/sesAn2ZPpoeT3ihH5FqH7dQkGWeGg1bA
FIaVXm+gMAssaj+k52g/+CnY4KZUHrSkg48OoRB+2a6FqGS8BLeCa+v+zaJCk2fz
EI/NeJwL4Asz1F4AwkEu5X9y8eEGArCXoP0OpYpCxIBZ+7MiKKDOoNf0a/0nOhvs
29LIIOnG+x0/RDfRgFObrF9geKpVTpI=
=ZhFE
-----END PGP PUBLIC KEY BLOCK-----
S4_VENDOR_KEY
}

s4_vendor_key_matches() {
    local digest
    s4_safe_path "$S4_GPG_KEY" || return 1
    [[ -f $S4_GPG_KEY && ! -L $S4_GPG_KEY ]] || return 1
    [[ $(stat -c %s -- "$S4_GPG_KEY") == 983 ]] || return 1
    digest=$(timeout --kill-after=5s 15s sha256sum -- "$S4_GPG_KEY") || return 1
    [[ ${digest%% *} == "$S4_VENDOR_KEY_SHA256" ]]
}

s4_rpm_database_path() {
    local keyring database
    keyring=$(timeout --kill-after=5s 30s rpm --eval '%{?_keyring}') || return 75
    # RPM 4.18 defaults to rpmdb for an unset keyring selector. A filesystem
    # keyring must not be falsely certified by observing a different database.
    [[ -z $keyring || $keyring == rpmdb ]] || return 75
    database=$(timeout --kill-after=5s 30s rpm --eval '%{_dbpath}') || return 75
    [[ $database == /* && ${#database} -le 4096 ]] || return 75
    # A distro-owned leaf alias is allowed only inside trusted ancestry. Check
    # that ancestry before following it so an unprivileged alias cannot redirect
    # RPM while the persistence check observes an unrelated safe directory.
    s4_safe_path "$(dirname -- "$database")" || return 75
    if [[ -L $database ]]; then
        [[ $(stat -c %u -- "$database") == 0 ]] || return 75
    fi
    database=$(readlink -e -- "$database") || return 75
    s4_safe_path "$database" || return 75
    [[ -d $database ]] || return 75
    printf '%s\n' "$database"
}

s4_rpm_vendor_key_matches() {
    local encoded digest
    # PUBKEYS is the actual base64 packet material RPM loads, not a description
    # or a short key ID. Bound output and compare the complete decoded keyblock.
    encoded=$(timeout --kill-after=5s 30s rpm -q --qf '[%{PUBKEYS}\n]' \
        gpg-pubkey-3135ce90-5e6fda74 | head -c 2049) || return 1
    (( ${#encoded} > 0 && ${#encoded} <= 2048 )) || return 1
    digest=$(printf '%s\n' "$encoded" | base64 --decode | sha256sum) || return 1
    [[ ${digest%% *} == 38ced48482bda02f404a772c09c3572440a3f597bf15cc3b7abadaef60be2e81 ]]
}

s4_verify_trust_anchor() {
    local database
    s4_vendor_key_matches || return 1
    database=$(s4_rpm_database_path) || return 1
    s4_rpm_vendor_key_matches || return 1
    # An earlier failed publication/import barrier can leave correct bytes
    # visible. Re-establish persistence even on the existing healthy path.
    timeout --kill-after=5s 30s sync -f -- "$(dirname -- "$S4_GPG_KEY")" \
        "$database" "$(dirname -- "$database")" || return 1
    s4_vendor_key_matches && s4_rpm_vendor_key_matches
}

s4_apply_trust_anchor() {
    local material digest database
    database=$(s4_rpm_database_path) || return 75
    material=$(s4_vendor_key_material) || return 75
    digest=$(printf '%s\n' "$material" | sha256sum) || return 75
    [[ ${digest%% *} == "$S4_VENDOR_KEY_SHA256" ]] || {
        s4_log 'Embedded vendor material differs from its vetted pin; repair is deferred.'
        return 75
    }
    # Only our own regular-file target is replaced. Wrong-kind, linked or
    # untrusted paths remain untouched under the accepted write contract.
    s4_atomic_write "$S4_GPG_KEY" 0600 <<<"$material" || return $?
    s4_vendor_key_matches || return 75
    if ! s4_rpm_vendor_key_matches; then
        timeout --kill-after=5s 30s rpm --import "$S4_GPG_KEY" </dev/null || return 75
    fi
    # Import exit zero is insufficient; require actual admitted packets and a
    # persistence barrier, including on an already-registered retry.
    s4_verify_trust_anchor || return 75
}

s4_repositories() {
    # Isolate our transactions from user, preview, and third-party repositories.
    [[ -f $S4_GPG_KEY && ! -L $S4_GPG_KEY ]] || {
        s4_log 'The Azure Linux RPM trust anchor is unavailable; signature checks stay enabled.'
        return 75
    }
    s4_safe_path "$S4_GPG_KEY" || return $?
    local repository
    for repository in base extended; do
        s4_atomic_write "$S4_STATE/repos/$repository.repo" 0600 <<EOF || return $?
[azurelinux3s4-$repository]
name=Azure Linux 3.0 production $repository
baseurl=https://packages.microsoft.com/azurelinux/3.0/prod/$repository/$S4_ARCH/
gpgkey=file://$S4_GPG_KEY
gpgcheck=1
repo_gpgcheck=1
sslverify=1
enabled=1
skip_if_unavailable=0
timeout=30
retries=2
EOF
    done
    s4_atomic_write "$S4_STATE/tdnf.conf" 0600 <<EOF
[main]
gpgcheck=1
installonly_limit=3
installonlypkgs=kernel kernel-mshv kernel-uvm kernel-uki kernel-64k kernel-hwe
clean_requirements_on_remove=0
repodir=$S4_STATE/repos
cachedir=/var/cache/tdnf/azurelinux3s4
plugins=1
pluginpath=$(dirname -- "$S4_PLUGIN_LIBRARY")
pluginconfpath=$(dirname -- "$S4_PLUGIN_CONFIG")
EOF
}

s4_verify_rpm_artifacts() (
    # Admission evidence only. A future update executor must consume the same
    # admitted snapshots; this API never installs or promises freshness.
    (( $# >= 1 && $# <= 128 )) || return 64
    command -v python3 >/dev/null && command -v rpmkeys >/dev/null || return 75
    s4_safe_path "$S4_RUN" && s4_safe_path "$S4_GPG_KEY" || return 75
    local path directory result=0 evidence
    if [[ -n $S4_ADMISSION_DESTINATION ]]; then
        s4_safe_path "$S4_ADMISSION_DESTINATION" || return 75
    fi
    for path in "$@"; do
        s4_safe_path "$path" || return 75
    done
    directory=$(mktemp -d "$S4_RUN/package-admission.XXXXXX") || return 75
    trap 'rm -rf -- "$directory"' EXIT
    if timeout --signal=TERM --kill-after=5s 15m python3 -I - \
        "$directory" "$S4_GPG_KEY" "$S4_VENDOR_KEY_SHA256" \
        "$S4_VENDOR_FINGERPRINT" "$S4_ADMISSION_DESTINATION" "$@" >"$directory/result.json" <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile

try:
    root = Path(sys.argv[1])
    home, database = root / "home", root / "rpmdb"
    home.mkdir(mode=0o700)
    database.mkdir(mode=0o700)
    environment = {"PATH": os.environ["PATH"], "HOME": str(home), "LC_ALL": "C", "LANG": "C"}
    common = ["--noplugins", "--dbpath", str(database), "--define", "_keyring rpmdb",
              "--define", "_pkgverify_level all", "--define", "_pkgverify_flags 0"]

    def command_limits():
        # This child-only limit bounds diagnostics/database files without
        # limiting the parent copying a large, bounded package snapshot.
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))

    def run(tool, *arguments, limit=30):
        # A malformed RPM cannot make diagnostics consume unbounded RAM/disk.
        with tempfile.TemporaryFile(dir=root) as output:
            result = subprocess.run([tool, *common, *arguments], stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=output, env=environment, timeout=limit,
                                    preexec_fn=command_limits)
            output.seek(0)
            data = output.read(65537)
        if result.returncode or len(data) > 65536:
            raise ValueError(tool + " did not provide bounded successful evidence")
        return data.decode("ascii")

    def snapshot(source, target, maximum):
        source = Path(source)
        if not source.is_absolute() or len(os.fsencode(source)) > 4096:
            raise ValueError("artifact path is not a bounded absolute path")
        observed = source.lstat()
        if not stat.S_ISREG(observed.st_mode):
            raise ValueError("input is not a regular file before opening")
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode)
                    or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)
                    or before.st_uid not in (0, os.geteuid())
                    or before.st_mode & 0o022 or not 0 < before.st_size <= maximum):
                raise ValueError("input is not an admissible bounded regular file")
            digest = hashlib.sha256()
            total = 0
            with target.open("xb") as destination:
                target.chmod(0o600)
                while block := stream.read(1024 * 1024):
                    total += len(block)
                    if total > maximum:
                        raise ValueError("input grew beyond its admission bound")
                    digest.update(block)
                    destination.write(block)
            after = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                      value.st_mtime_ns, value.st_ctime_ns)
            if identity(before) != identity(after) or total != before.st_size:
                raise ValueError("input changed while its private snapshot was copied")
        return digest.hexdigest(), total

    key = root / "vendor.asc"
    digest, size = snapshot(sys.argv[2], key, 983)
    if size != 983 or digest != sys.argv[3]:
        raise ValueError("private admission key differs from its vetted pin")
    run("rpm", "--initdb")
    run("rpm", "--import", str(key))
    names = run("rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\\n").splitlines()
    if names != ["gpg-pubkey-3135ce90-5e6fda74"]:
        raise ValueError("private RPM database contains a missing or additional identity")
    packets = run("rpm", "-q", "--qf", "[%{PUBKEYS}\\n]", names[0])
    decoded = base64.b64decode("".join(packets.splitlines()), validate=True)
    if hashlib.sha256(decoded).hexdigest() != "38ced48482bda02f404a772c09c3572440a3f597bf15cc3b7abadaef60be2e81":
        raise ValueError("actual private RPM key packets differ from the vetted identity")

    signature = re.compile(r"Header V[34] RSA/SHA(?:256|384|512) Signature, key ID 3135ce90: OK")
    package_signature = re.compile(r"V[34] RSA/SHA(?:256|384|512) Signature, key ID 3135ce90: OK")
    strong_header = re.compile(r"Header SHA(?:256|384|512) digest: OK")
    strong_payload = re.compile(r"Payload SHA(?:256|384|512) digest: OK")
    additional = {"Header SHA1 digest: OK", "MD5 digest: OK"}
    admitted, total = [], 0
    destination = Path(sys.argv[5]) if sys.argv[5] else root
    if destination != root:
        observed = destination.lstat()
        if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid not in (0, os.geteuid())
                or observed.st_mode & 0o077 or any(destination.iterdir())):
            raise ValueError("retained snapshot directory is not private and empty")
    for index, name in enumerate(sys.argv[6:]):
        artifact = destination / (str(index) + ".rpm")
        digest, size = snapshot(name, artifact, 512 * 1024 * 1024)
        total += size
        if total > 1024 * 1024 * 1024:
            raise ValueError("artifact batch exceeds its one-GiB bound")
        lines = run("rpmkeys", "--checksig", "--verbose", str(artifact), limit=120).splitlines()
        if not lines or lines[0] != str(artifact) + ":":
            raise ValueError("native verifier did not identify the private artifact")
        records = [line.strip() for line in lines[1:]]
        if (not any(signature.fullmatch(line) for line in records)
                or not any(strong_header.fullmatch(line) for line in records)
                or not any(strong_payload.fullmatch(line) for line in records)
                or any(not (signature.fullmatch(line) or package_signature.fullmatch(line) or strong_header.fullmatch(line)
                            or strong_payload.fullmatch(line) or line in additional) for line in records)):
            raise ValueError("native evidence lacks a pinned signature and strong header/payload digests")
        admitted.append({"path": name, "sha256": digest, "bytes": size})
    print(json.dumps({"schema": 1, "vendor_fingerprint": sys.argv[4], "artifacts": admitted,
                      "installs_performed": False, "snapshots_retained": destination != root,
                      "freshness_proven": False}, sort_keys=True))
except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: package admission deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
    then
        evidence=$(head -c 1048577 -- "$directory/result.json") || result=75
        (( ${#evidence} <= 1048576 )) || result=75
    else
        result=75
    fi
    # Publish no success until ordinary success/failure/timeout cleanup finishes.
    if ! rm -rf -- "$directory"; then
        s4_log 'Private package admission cleanup failed.'
        return 75
    fi
    trap - EXIT
    (( result == 0 )) || return 75
    printf '%s\n' "$evidence"
)

s4_tdnf() {
    if [[ -n $S4_DOWNLOAD_DIRECTORY ]]; then
        [[ $# == 3 && $1 == upgrade && $2 == --downloadonly && $3 == "--downloaddir=$S4_DOWNLOAD_DIRECTORY" ]] || return 78
        s4_safe_path "$S4_DOWNLOAD_DIRECTORY" || return 75
        [[ -d $S4_DOWNLOAD_DIRECTORY && ! -L $S4_DOWNLOAD_DIRECTORY ]] || return 75
    else
        [[ $# == 1 && $1 == makecache ]] || {
        s4_log 'The signed update executor is unfinished; package-changing operations are deferred.'
            return 78
        }
    fi
    s4_verify_metadata || return 75
    s4_safe_path "$S4_GPG_KEY" || return 75
    [[ -f $S4_GPG_KEY && ! -L $S4_GPG_KEY ]] || return 75
    local limit=15m
    [[ ${1:-} != makecache ]] || limit=5m
    # The native plugin uses GnuPG's keyring, not the repository's gpgkey option.
    # Build a new keyring per operation; never inherit an administrator's keys,
    # trust database, home configuration, agent, or network key retrieval.
    timeout --signal=TERM --kill-after=30s "$limit" \
        python3 -I - "$S4_RUN" "$S4_GPG_KEY" "$S4_VENDOR_KEY_SHA256" \
        "$S4_VENDOR_FINGERPRINT" "$S4_STATE/tdnf.conf" "$limit" "$S4_DOWNLOAD_DIRECTORY" "$@" <<'PY'
import hashlib
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import tempfile
import time

try:
    # Read a bounded snapshot; GnuPG imports that snapshot, not a second read of
    # a potentially replaced source key. The SHA-256 pins all keyblock packets.
    with open(sys.argv[2], "rb") as source:
        key = source.read(65537)
    if len(key) > 65536 or hashlib.sha256(key).hexdigest() != sys.argv[3]:
        raise ValueError("Azure Linux vendor key does not match the vetted keyblock")
    with tempfile.TemporaryDirectory(prefix="transaction.", dir=sys.argv[1]) as directory:
        root = Path(directory)
        home = root / "gnupg"
        home.mkdir(mode=0o700)
        (home / "gpg.conf").write_text(
            "no-autostart\ndisable-dirmngr\nno-auto-key-retrieve\nno-auto-key-import\n")
        snapshot = root / "vendor.asc"
        snapshot.write_bytes(key)
        environment = dict(os.environ, GNUPGHOME=str(home), LC_ALL="C")
        environment.pop("GPG_AGENT_INFO", None)
        gpg = ["gpg2", "--no-options", "--homedir", str(home), "--batch", "--no-tty",
               "--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve", "--no-auto-key-import"]
        def run(*arguments, **options):
            return subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, env=environment, **options)
        imported = run(*gpg, "--import", str(snapshot), timeout=15)
        if imported.returncode:
            raise ValueError("vetted vendor key could not be imported into its private keyring")
        listed = run(*gpg, "--with-colons", "--list-keys", timeout=15)
        records = [line.split(":") for line in listed.stdout.splitlines()]
        public = [record for record in records if record[0] == "pub"]
        fingerprints = [record[9] for record in records if record[0] == "fpr" and len(record) > 9]
        if (listed.returncode or len(public) != 1 or len(public[0]) < 10
                or fingerprints != [sys.argv[4]] or public[0][1] in ("r", "e", "d")
                or any(record[0] in ("sec", "ssb") for record in records)):
            raise ValueError("private metadata keyring did not prove the exact vendor identity")
        # Verbose loader evidence is mandatory for this actual operation as well
        # as the separate integrity/invalid-signature challenge before it.
        command = ["tdnf", "-v", "-c", sys.argv[5], "--releasever=3.0", "--refresh", "-y",
                   "--disableplugin=*", "--enableplugin=tdnfrepogpgcheck", *sys.argv[8:]]
        if sys.argv[7]:
            incoming = Path(sys.argv[7])
            observed = incoming.lstat()
            if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid()
                    or observed.st_mode & 0o077 or any(incoming.iterdir())
                    or any(character not in "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                           for character in str(incoming) + str(root))):
                raise ValueError("download workspace is not an empty private directory")
            cache = root / "cache"
            cache.mkdir(mode=0o700)
            configuration = Path(sys.argv[5]).read_text()
            lines = configuration.splitlines()
            if sum(line.startswith("cachedir=") for line in lines) != 1:
                raise ValueError("download cache policy is ambiguous")
            (root / "download.conf").write_text("\n".join(
                "cachedir=" + str(cache) if line.startswith("cachedir=") else line
                for line in lines) + "\n")
            command[3] = str(root / "download.conf")
            unit = "azurelinux3s4-download-" + root.name.removeprefix("transaction.") + ".service"
            probe = """import os, sys
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
if any(int(status[name].strip(), 16) for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb')) or status['NoNewPrivs'].strip() != '1':
    raise SystemExit('download sandbox lacks its privilege restriction')
for path in ('/', '/etc', '/usr', '/var/lib', '/var/lib/rpm'):
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise SystemExit('download sandbox lacks read-only system protection: ' + path)
for path in ('/run/systemd/private', '/run/dbus/system_bus_socket'):
    if os.access(path, os.R_OK | os.W_OK):
        raise SystemExit('download sandbox exposes a privileged manager socket')
print('S4_DOWNLOAD_SANDBOX_VERIFIED', flush=True)
os.execvp(sys.argv[1], sys.argv[1:])
"""
            sandbox = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
                       "--unit=" + unit, "--property=RuntimeMaxSec=14min", "--property=TimeoutStopSec=15s",
                       "--property=KillMode=control-group", "--property=ProtectSystem=strict",
                       "--property=ReadWritePaths=" + str(root) + " " + str(incoming),
                       "--property=ProtectHome=yes", "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
                       "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
                       "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
                       "--property=ProtectKernelLogs=yes", "--property=ProtectControlGroups=yes",
                       "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
                       "--property=LockPersonality=yes", "--property=UMask=0077",
                       "--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket",
                       "--property=LimitFSIZE=536870912", "--property=MemoryMax=768M",
                       "--property=UnsetEnvironment=RPM_CONFIGDIR RPM_POPTEXEC_PATH GPG_AGENT_INFO LD_PRELOAD LD_LIBRARY_PATH",
                       "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
                       "--setenv=HOME=" + str(home), "--setenv=GNUPGHOME=" + str(home), "--",
                       "python3", "-I", "-c", probe, *command]
            # Stream diagnostics into a bounded buffer. Watch the flat incoming
            # directory while tdnf runs, rather than admitting a huge completed download.
            process = subprocess.Popen(sandbox, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, env=environment)
            completed = False
            try:
                output = bytearray()
                deadline = time.monotonic() + 800
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while selector.get_map():
                        if time.monotonic() >= deadline:
                            raise ValueError("download deadline expired")
                        entries = list(incoming.iterdir())
                        sizes = [entry.lstat() for entry in entries]
                        if (len(entries) > 128 or any(not stat.S_ISREG(value.st_mode)
                                or value.st_size > 512 * 1024 * 1024 for value in sizes)
                                or sum(value.st_size for value in sizes) > 1024 * 1024 * 1024):
                            raise ValueError("download exceeded its regular-file/count/size bounds")
                        for event, _ in selector.select(0.2):
                            data = os.read(event.fd, 65536)
                            if not data:
                                selector.unregister(event.fileobj)
                            else:
                                output.extend(data)
                                if len(output) > 1024 * 1024:
                                    raise ValueError("download diagnostics exceeded their bound")
                code = process.wait(timeout=max(1, deadline - time.monotonic()))
                completed = True
                transaction = subprocess.CompletedProcess(sandbox, code, output.decode("utf-8", "strict"), "")
                if "S4_DOWNLOAD_SANDBOX_VERIFIED\n" not in transaction.stdout:
                    raise ValueError("download sandbox enforcement was not positively observed")
            finally:
                if not completed:
                    stopped = subprocess.run(["systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                                             capture_output=True, timeout=30)
                    process.kill()
                    process.wait(timeout=15)
                    if stopped.returncode:
                        raise ValueError("download service shutdown could not be confirmed")
        else:
            transaction = run(*command, timeout=240)
        print(transaction.stdout, end="")
        print(transaction.stderr, end="", file=sys.stderr)
        output = transaction.stdout + transaction.stderr
        if transaction.returncode:
            sys.exit(transaction.returncode if 0 < transaction.returncode < 126 else 75)
        if "Loaded plugin: tdnfrepogpgcheck" not in output or "Error loading plugin" in output:
            raise ValueError("native metadata verifier participation was not observed")
except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: trusted metadata transaction deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
}

s4_verify_repository_trust() {
    # A stored success marker is insufficient. Re-import the pinned key and
    # require a fresh native signed refresh of both enabled production repos.
    s4_tdnf makecache
}

s4_update_store() {
    # Two bounded slots preserve the last durable batch while preparing its
    # replacement. A visible pointer is re-flushed before the other slot is reused.
    local action=$1 directory=${2:-} receipt=${3:-}
    s4_safe_path "$S4_STATE/updates" || return 75
    timeout --kill-after=5s 5m python3 -I - "$action" "$S4_STATE/updates" \
        "$S4_VENDOR_FINGERPRINT" "$directory" "$receipt" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

try:
    action, root, fingerprint = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
    marker = b"azurelinux3s4-update-slot-v1\n"

    def inspect(path, directory=False, private=True):
        value = path.lstat()
        if (not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
                or value.st_uid != os.geteuid() or value.st_mode & (0o077 if private else 0o022)
                or (not directory and value.st_nlink != 1)):
            raise ValueError("update store contains an unsafe object: " + str(path))
        return value

    def read(path, maximum=1048576):
        inspect(path)
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("update record exceeds its bound")
        return data

    def flush(path):
        inspect(path, path.is_dir())
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def barrier(*paths):
        subprocess.run(["sync", "-f", "--", *map(str, paths)], stdin=subprocess.DEVNULL,
                       check=True, timeout=30)

    def write(path, data, mode):
        if path.exists() or path.is_symlink():
            inspect(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

    def inventory(slot):
        inspect(slot, True)
        names = {entry.name for entry in slot.iterdir()}
        if not names <= {"owner", "manifest.json", "packages"}:
            raise ValueError("refusing foreign slot contents")
        if "owner" not in names:
            if names:
                raise ValueError("nonempty slot has no ownership record")
            return []
        identity = read(slot / "owner", 128)
        if identity != marker:
            # Initial creation can be interrupted before the complete marker is
            # written. Only its bounded prefix in an otherwise empty slot is
            # recognized; foreign data and every wrong-kind object remain refused.
            if names == {"owner"} and marker.startswith(identity):
                return []
            raise ValueError("slot ownership record is foreign")
        if "manifest.json" in names:
            inspect(slot / "manifest.json")
        files = []
        if "packages" in names:
            inspect(slot / "packages", True)
            files = list((slot / "packages").iterdir())
            if len(files) > 128:
                raise ValueError("slot contains too many package objects")
            for path in files:
                if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})\.rpm", path.name) or int(path.stem) > 127:
                    raise ValueError("refusing foreign package name")
                inspect(path)
        return files

    def validate(pointer, persist):
        if (not isinstance(pointer, dict) or set(pointer) != {"schema", "slot", "manifest_sha256"}
                or pointer["schema"] != 1 or pointer["slot"] not in ("0", "1")
                or not re.fullmatch(r"[0-9a-f]{64}", str(pointer["manifest_sha256"]))):
            raise ValueError("current update pointer is malformed")
        slot = root / ("slot" + pointer["slot"])
        files = inventory(slot)
        material = read(slot / "manifest.json")
        if hashlib.sha256(material).hexdigest() != pointer["manifest_sha256"]:
            raise ValueError("current update manifest does not match its pointer")
        proof = json.loads(material)
        if (set(proof) != {"schema", "vendor_fingerprint", "packages", "installs_performed", "freshness_proven"}
                or proof["schema"] != 1 or proof["vendor_fingerprint"] != fingerprint
                or proof["installs_performed"] is not False or proof["freshness_proven"] is not False
                or not isinstance(proof["packages"], list) or len(proof["packages"]) > 128):
            raise ValueError("current update manifest policy is unsupported")
        expected, total = [], 0
        for index, record in enumerate(proof["packages"]):
            path = slot / "packages" / (str(index) + ".rpm")
            if (not isinstance(record, dict) or set(record) != {"file", "bytes", "sha256"}
                    or record["file"] != "packages/" + path.name or type(record["bytes"]) is not int
                    or not 0 < record["bytes"] <= 512 * 1024 * 1024
                    or not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"]))):
                raise ValueError("current update package record is malformed")
            value = inspect(path)
            if value.st_mode & 0o777 != 0o400 or value.st_size != record["bytes"]:
                raise ValueError("retained update package mode/size changed")
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)
            if digest.hexdigest() != record["sha256"]:
                raise ValueError("retained update package bytes changed")
            total += record["bytes"]
            expected.append(path)
            if persist:
                flush(path)
        if total > 1024 * 1024 * 1024 or set(files) != set(expected):
            raise ValueError("retained batch size/contents differ from its manifest")
        if persist:
            for path in (slot / "owner", slot / "manifest.json", slot / "packages", slot, root / "current.json", root):
                flush(path)
            barrier(slot, root, root.parent)
            if json.loads(read(root / "current.json")) != pointer:
                raise ValueError("current pointer changed after its persistence barrier")
        return slot

    inspect(root, True)
    current = root / "current.json"
    pointer = json.loads(read(current)) if current.exists() or current.is_symlink() else None
    if action == "begin":
        if pointer is not None:
            validate(pointer, True)
        name = "slot1" if pointer and pointer["slot"] == "0" else "slot0"
        slot = root / name
        if slot.exists() or slot.is_symlink():
            files = inventory(slot)
            # Only the recognized private slot and its bounded regular files
            # are reusable; ordinary foreign/wrong-kind objects are preserved.
            for path in files:
                path.unlink()
            if (slot / "manifest.json").exists():
                (slot / "manifest.json").unlink()
            # Keep the ownership record and empty package directory throughout
            # recycling. An interruption must not create an unrecognized slot.
        else:
            slot.mkdir(mode=0o700)
        if not (slot / "owner").exists() or read(slot / "owner", 128) != marker:
            write(slot / "owner", marker, 0o600)
        (slot / "packages").mkdir(mode=0o700, exist_ok=True)
        flush(slot)
        barrier(slot, root, root.parent)
        print(slot)
    elif action == "list":
        incoming = Path(sys.argv[4])
        inspect(incoming, True)
        files = sorted(incoming.iterdir())
        sizes = [inspect(path, private=False) for path in files]
        if (len(files) > 128 or any(not path.name.endswith(".rpm") for path in files)
                or any(not 0 < value.st_size <= 512 * 1024 * 1024 for value in sizes)
                or sum(value.st_size for value in sizes) > 1024 * 1024 * 1024):
            raise ValueError("download batch is not bounded regular RPM files")
        for path in files:
            sys.stdout.buffer.write(os.fsencode(path) + b"\0")
    elif action == "commit":
        slot = Path(sys.argv[4])
        if slot not in (root / "slot0", root / "slot1") or (pointer and slot.name == "slot" + pointer["slot"]):
            raise ValueError("candidate slot is not independent of the current slot")
        inventory(slot)
        receipt = json.loads(read(Path(sys.argv[5])))
        if (receipt.get("schema") != 1 or receipt.get("vendor_fingerprint") != fingerprint
                or receipt.get("snapshots_retained") is not True or receipt.get("installs_performed") is not False
                or receipt.get("freshness_proven") is not False or not isinstance(receipt.get("artifacts"), list)):
            raise ValueError("retained admission evidence is malformed")
        records = [{"file": "packages/" + str(index) + ".rpm", "bytes": value["bytes"], "sha256": value["sha256"]}
                   for index, value in enumerate(receipt["artifacts"])]
        for path in inventory(slot):
            path.chmod(0o400)
        manifest = json.dumps({"schema": 1, "vendor_fingerprint": fingerprint, "packages": records,
                               "installs_performed": False, "freshness_proven": False}, sort_keys=True).encode() + b"\n"
        write(slot / "manifest.json", manifest, 0o400)
        new = {"schema": 1, "slot": slot.name[-1], "manifest_sha256": hashlib.sha256(manifest).hexdigest()}
        # Validate bytes against the same admission receipt BEFORE publication.
        validate(new, False)
        for path in [*inventory(slot), slot / "owner", slot / "manifest.json", slot / "packages", slot]:
            flush(path)
        barrier(slot, root, root.parent)
        temporary = root / "current.next"
        write(temporary, json.dumps(new, sort_keys=True).encode() + b"\n", 0o600)
        temporary.replace(current)
        flush(root)
        barrier(root, root.parent)
        validate(new, True)
        print(json.dumps(new, sort_keys=True))
    elif action in ("verify", "plan"):
        if pointer is None:
            raise ValueError("no signed update batch is prepared")
        slot = validate(pointer, True)
        if action == "plan":
            proof = json.loads(read(slot / "manifest.json"))
            print(json.dumps({"schema": 1, "manifest_sha256": pointer["manifest_sha256"],
                              "packages": [{**record, "path": str(slot / record["file"])}
                                           for record in proof["packages"]]}, sort_keys=True))
    else:
        raise ValueError("unknown update-store operation")
except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: update preparation deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
}

s4_prepare_updates() (
    command -v systemd-run >/dev/null && command -v rpmkeys >/dev/null || return 75
    s4_directory "$S4_STATE/updates" 0700 || return 75
    local directory slot evidence
    slot=$(s4_update_store begin) || return 75
    directory=$(mktemp -d "$S4_RUN/updates.XXXXXX") || return 75
    trap 'rm -rf -- "$directory"' EXIT
    mkdir -m 0700 -- "$directory/incoming" || return 75
    local S4_DOWNLOAD_DIRECTORY=$directory/incoming
    if ! s4_tdnf upgrade --downloadonly "--downloaddir=$S4_DOWNLOAD_DIRECTORY" >"$directory/download.log"; then
        cat -- "$directory/download.log" >&2
        return 75
    fi
    cat -- "$directory/download.log" >&2
    s4_update_store list "$directory/incoming" >"$directory/files" || return 75
    local -a packages=()
    mapfile -d '' -t packages <"$directory/files"
    if (( ${#packages[@]} )); then
        local S4_ADMISSION_DESTINATION=$slot/packages
        s4_verify_rpm_artifacts "${packages[@]}" >"$directory/receipt.json" || return 75
    else
        # Empty output is not proof that the solver found no work. Require its
        # explicit native no-action observation after the signed refresh.
        awk '$0 == "Nothing to do." { found=1 } END { exit !found }' "$directory/download.log" || return 75
        printf '{"schema":1,"vendor_fingerprint":"%s","artifacts":[],"installs_performed":false,"snapshots_retained":true,"freshness_proven":false}\n' \
            "$S4_VENDOR_FINGERPRINT" >"$directory/receipt.json"
    fi
    evidence=$(s4_update_store commit "$slot" "$directory/receipt.json") || return 75
    rm -rf -- "$directory" || return 75
    trap - EXIT
    s4_log 'Signed update batch prepared; no packages were installed.'
    printf '%s\n' "$evidence"
)

s4_rpm_test_program() {
    # The public RPM 4.18.2 ABI permits mixed upgrade/install-only elements.
    # TEST only: no plugins/scripts/triggers. Capacity is explicitly unproved;
    # RPM treats a read-only mount as zero available blocks even in TEST mode.
    cat <<'PY'
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

try:
    root, database, architecture = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapBnd", "CapAmb"))
            or status["NoNewPrivs"].strip() != "1"):
        raise ValueError("RPM test sandbox lacks its privilege restriction")
    for path in (Path("/"), Path("/etc"), Path("/usr"), Path("/var/lib"), database,
                 root / "packages", root / "vendor.asc"):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise ValueError("RPM test sandbox lacks read-only protection: " + str(path))
    for path in ("/run/systemd/private", "/run/dbus/system_bus_socket"):
        if os.access(path, os.R_OK | os.W_OK):
            raise ValueError("RPM test sandbox exposes a privileged manager socket")
    if {entry.name for entry in Path("/sys/class/net").iterdir()} != {"lo"}:
        raise ValueError("RPM test sandbox exposes host network interfaces")

    plan = json.loads((root / "plan.json").read_text())
    admitted = json.loads((root / "admission.json").read_text())
    records = plan["packages"]
    if (set(plan) != {"schema", "manifest_sha256", "packages"} or plan["schema"] != 1
            or not re.fullmatch(r"[0-9a-f]{64}", plan["manifest_sha256"])
            or not isinstance(records, list) or len(records) > 128
            or admitted.get("snapshots_retained") is not True or admitted.get("installs_performed") is not False
            or admitted.get("freshness_proven") is not False or admitted.get("schema") != 1
            or admitted.get("vendor_fingerprint") != "2BC94FFF7015A5F28F1537AD0CD9FED33135CE90"
            or len(admitted["artifacts"]) != len(records)):
        raise ValueError("batch context or repeated admission is malformed")
    paths, total = [], 0
    def digest(path):
        observed = path.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
                or observed.st_mode & 0o777 != 0o400 or observed.st_nlink != 1
                or not 0 < observed.st_size <= 512 * 1024 * 1024):
            raise ValueError("test input is not the private read-only snapshot")
        value = hashlib.sha256()
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                value.update(block)
        return value.hexdigest(), observed.st_size
    for index, (record, artifact) in enumerate(zip(records, admitted["artifacts"])):
        if (set(record) != {"file", "path", "bytes", "sha256"}
                or record["file"] != "packages/" + str(index) + ".rpm"
                or set(artifact) != {"path", "bytes", "sha256"}
                or artifact != {"path": record["path"], "bytes": record["bytes"], "sha256": record["sha256"]}):
            raise ValueError("repeated admission differs from the retained manifest")
        path = root / "packages" / (str(index) + ".rpm")
        if digest(path) != (record["sha256"], record["bytes"]):
            raise ValueError("native test bytes differ from the admitted snapshots")
        paths.append(os.fsencode(path))
        total += record["bytes"]
    if total > 1024 * 1024 * 1024:
        raise ValueError("test batch exceeds its aggregate bound")
    key = root / "vendor.asc"
    if digest(key) != ("1092f37ec429e58bf9c7f898df17c3c32eb2ce3c4c037afb8ffe2d2b42e16e89", 983):
        raise ValueError("native test key differs from its vetted pin")

    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, "RPMVERSION").value != b"4.18.2":
        raise ValueError("native RPM ABI has not been vetted for this test")
    pointer, integer, unsigned, string = C.c_void_p, C.c_int, C.c_uint, C.c_char_p
    def bind(name, result, *arguments):
        function = getattr(lib, name)
        function.restype, function.argtypes = result, arguments
        return function
    signatures = {
        "rpmReadConfigFiles": (integer, string, string), "rpmtsCreate": (pointer,),
        "rpmPushMacro": (integer, pointer, string, string, string, integer),
        "rpmtsFree": (pointer, pointer), "rpmtsSetRootDir": (integer, pointer, string),
        "rpmtsSetDBMode": (integer, pointer, integer), "rpmtsOpenDB": (integer, pointer, integer),
        "rpmtsSetFlags": (unsigned, pointer, unsigned), "rpmtsFlags": (unsigned, pointer),
        "rpmtsSetVSFlags": (unsigned, pointer, unsigned), "rpmtsSetVfyFlags": (unsigned, pointer, unsigned),
        "rpmtsSetVfyLevel": (integer, pointer, integer), "rpmtsSetKeyring": (integer, pointer, pointer),
        "rpmKeyringNew": (pointer,), "rpmPubkeyRead": (pointer, string),
        "rpmKeyringAddKey": (integer, pointer, pointer), "rpmPubkeyFree": (pointer, pointer),
        "rpmKeyringFree": (pointer, pointer), "Fopen": (pointer, string, string),
        "Ferror": (integer, pointer), "Fclose": (integer, pointer),
        "rpmReadPackageFile": (integer, pointer, pointer, string, C.POINTER(pointer)),
        "headerGetString": (string, pointer, integer), "headerFree": (pointer, pointer),
        "headerIsEntry": (integer, pointer, integer),
        "rpmtsAddInstallElement": (integer, pointer, pointer, string, integer, pointer),
        "rpmtsCheck": (integer, pointer), "rpmtsOrder": (integer, pointer),
        "rpmtsRun": (integer, pointer, pointer, unsigned), "rpmtsProblems": (pointer, pointer),
        "rpmpsNumProblems": (integer, pointer), "rpmpsFree": (pointer, pointer),
        "rpmtsNElements": (integer, pointer), "rpmtsElement": (pointer, pointer, integer),
        "rpmteType": (integer, pointer), "rpmteN": (string, pointer),
        "rpmteNEVRA": (string, pointer), "rpmteKey": (string, pointer),
        "rpmtsInitIterator": (pointer, pointer, integer, pointer, C.c_size_t),
        "rpmdbNextIterator": (pointer, pointer), "rpmdbGetIteratorOffset": (unsigned, pointer),
        "rpmdbFreeIterator": (pointer, pointer), "headerExport": (pointer, pointer, C.POINTER(unsigned)),
        "rpmlogGetNrecsByMask": (integer, unsigned), "rpmlogSetMask": (integer, integer),
    }
    api = {name: bind(name, *signature) for name, signature in signatures.items()}
    libc = C.CDLL(None)
    libc.free.argtypes, libc.free.restype = [pointer], None
    if api["rpmReadConfigFiles"](None, None):
        raise ValueError("native RPM configuration could not be loaded")
    if api["rpmPushMacro"](None, b"_dbpath", None, os.fsencode(database), -7):
        raise ValueError("native RPM could not select the checked installed database")
    api["rpmlogSetMask"](15)  # Emergency through error; native warnings are not success records.
    def errors():
        if api["rpmlogGetNrecsByMask"](15):
            raise ValueError("native RPM reported an error")
    flags = 1 | 4 | 16 | 128  # TEST, NOSCRIPTS, NOTRIGGERS, NOPLUGINS.
    def transaction():
        ts = api["rpmtsCreate"]()
        if not ts:
            raise ValueError("native transaction allocation failed")
        try:
            if api["rpmtsSetRootDir"](ts, b"/") or api["rpmtsSetDBMode"](ts, os.O_RDONLY):
                raise ValueError("native read-only transaction policy failed")
            api["rpmtsSetFlags"](ts, flags)
            api["rpmtsSetVSFlags"](ts, 0)
            api["rpmtsSetVfyFlags"](ts, 0)
            api["rpmtsSetVfyLevel"](ts, 3)  # Digest AND signature, without administrator relaxation.
            keyring, pubkey = api["rpmKeyringNew"](), api["rpmPubkeyRead"](os.fsencode(key))
            try:
                if not keyring or not pubkey or api["rpmKeyringAddKey"](keyring, pubkey) or api["rpmtsSetKeyring"](ts, keyring):
                    raise ValueError("native in-memory pinned keyring could not be established")
            finally:
                if pubkey:
                    api["rpmPubkeyFree"](pubkey)
                if keyring:
                    api["rpmKeyringFree"](keyring)
            if api["rpmtsFlags"](ts) != flags or api["rpmtsOpenDB"](ts, os.O_RDONLY):
                raise ValueError("native TEST/read-only state was not observed")
            errors()
            return ts
        except BaseException:
            api["rpmtsFree"](ts)
            raise
    def baseline():
        # Header content + instance IDs observed before and after; not an RPM
        # mutation lock or authority to reuse this observation for installation.
        ts, iterator = transaction(), None
        try:
            iterator = api["rpmtsInitIterator"](ts, 0, None, 0)
            if not iterator:
                raise ValueError("installed header iteration failed")
            entries, total = [], 0
            while header := api["rpmdbNextIterator"](iterator):
                size = unsigned()
                material = api["headerExport"](header, C.byref(size))
                if not material:
                    raise ValueError("installed header export failed")
                try:
                    total += size.value
                    if not 0 < size.value <= 8 * 1024 * 1024 or total > 512 * 1024 * 1024 or len(entries) >= 32768:
                        raise ValueError("installed baseline exceeds its finite inspection bounds")
                    entries.append((api["rpmdbGetIteratorOffset"](iterator),
                                    hashlib.sha256(C.string_at(material, size.value)).hexdigest()))
                finally:
                    libc.free(material)
            errors()
            if not entries or len({entry[0] for entry in entries}) != len(entries):
                raise ValueError("installed header baseline is empty or ambiguous")
            return {"headers": len(entries), "sha256": hashlib.sha256(
                json.dumps(sorted(entries), separators=(",", ":")).encode()).hexdigest()}
        finally:
            if iterator:
                api["rpmdbFreeIterator"](iterator)
            api["rpmtsFree"](ts)
    before = baseline()
    ts = transaction()
    install_only = {b"kernel", b"kernel-mshv", b"kernel-uvm", b"kernel-uki", b"kernel-64k", b"kernel-hwe"}
    additions, removals = [], []
    pretrans = {}
    opened, consumed, callback_errors = {}, set(), []
    callback_type = C.CFUNCTYPE(pointer, pointer, integer, C.c_uint64, C.c_uint64, pointer, pointer)
    @callback_type
    def notify(header, what, amount, total, key, data):
        try:
            if what & ((1 << 15) | (1 << 16) | (1 << 17)):
                raise ValueError("native TEST attempted package script execution")
            if what in (4, 8):
                path = C.string_at(key) if key else None
                if path not in paths:
                    raise ValueError("native callback requested bytes outside the admitted snapshots")
                if what == 4:
                    if path in opened:
                        raise ValueError("native callback requested an already-open snapshot")
                    fd = api["Fopen"](path, b"r.ufdio")
                    if not fd or api["Ferror"](fd):
                        if fd:
                            api["Fclose"](fd)
                        raise ValueError("native callback could not open its admitted snapshot")
                    opened[path] = fd
                    consumed.add(path)
                    return fd
                fd = opened.pop(path, None)
                if not fd or api["Fclose"](fd):
                    raise ValueError("native callback could not close its snapshot")
        except (ValueError, OSError) as error:
            callback_errors.append(str(error))
        return None
    set_notify = bind("rpmtsSetNotifyCallback", integer, pointer, callback_type, pointer)
    try:
        if set_notify(ts, notify, None):
            raise ValueError("native snapshot callback could not be established")
        for path in paths:
            fd, header = api["Fopen"](path, b"r.ufdio"), pointer()
            try:
                if not fd or api["Ferror"](fd) or api["rpmReadPackageFile"](ts, fd, path, C.byref(header)) or not header:
                    raise ValueError("native signed snapshot header read failed")
                name, arch = api["headerGetString"](header, 1000), api["headerGetString"](header, 1022)
                if not name or not re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", name) or arch not in (architecture.encode(), b"noarch"):
                    raise ValueError("snapshot is not a target-architecture binary RPM")
                if api["rpmtsAddInstallElement"](ts, header, path, int(name not in install_only), None):
                    raise ValueError("native mixed transaction could not admit every input")
                pretrans[path] = bool(api["headerIsEntry"](header, 1151))
            finally:
                if header:
                    api["headerFree"](header)
                if fd and api["Fclose"](fd):
                    raise ValueError("native snapshot descriptor close failed")
        if api["rpmtsCheck"](ts):
            raise ValueError("native dependency check failed")
        def no_problems():
            problems = api["rpmtsProblems"](ts)
            try:
                if api["rpmpsNumProblems"](problems):
                    raise ValueError("native transaction has unresolved problems")
            finally:
                if problems:
                    api["rpmpsFree"](problems)
            errors()
        no_problems()
        if api["rpmtsOrder"](ts):
            raise ValueError("native transaction ordering failed")
        count = api["rpmtsNElements"](ts)
        if not len(paths) <= count <= 32768 + 128:
            raise ValueError("native transaction element count is inconsistent")
        for index in range(count):
            element = api["rpmtsElement"](ts, index)
            if not element:
                raise ValueError("native transaction element is missing")
            kind, name = api["rpmteType"](element), api["rpmteN"](element)
            identity = api["rpmteNEVRA"](element)
            if not identity or len(identity) > 1024:
                raise ValueError("native transaction identity is malformed")
            if kind == 1:
                additions.append({"snapshot": os.fsdecode(api["rpmteKey"](element)),
                                  "nevra": identity.decode("ascii"), "install_only": name in install_only})
            elif kind == 2 and name not in install_only:
                removals.append(identity.decode("ascii"))
            else:
                raise ValueError("native plan would remove a retained kernel or has an unknown element")
        if sorted(os.fsencode(value["snapshot"]) for value in additions) != sorted(paths):
            raise ValueError("native plan replaced or dropped an admitted input")
        if api["rpmtsFlags"](ts) != flags or api["rpmtsRun"](ts, None, (1 << 7) | (1 << 8)):
            # Only capacity/inode filters: all signature, dependency, file,
            # architecture and older/already-installed package checks remain.
            raise ValueError("native TEST transaction rejected the batch")
        if callback_errors or opened or consumed != set(paths):
            raise ValueError("native TEST did not consume and close exactly the admitted snapshots")
        no_problems()
    finally:
        for fd in opened.values():
            api["Fclose"](fd)
        api["rpmtsFree"](ts)
    after = baseline()
    if after != before:
        raise ValueError("installed header context changed during compatibility inspection")
    for index, record in enumerate(records):
        if digest(root / "packages" / (str(index) + ".rpm")) != (record["sha256"], record["bytes"]):
            raise ValueError("native test snapshots changed")
    for addition in additions:
        path = os.fsencode(addition.pop("snapshot"))
        index = paths.index(path)
        addition.update(file=records[index]["file"], sha256=records[index]["sha256"], bytes=records[index]["bytes"])
        addition["pretrans_present"] = pretrans[path]
    print(json.dumps({"schema": 1, "manifest_sha256": plan["manifest_sha256"],
                      "baseline": before, "additions": additions, "removals": removals,
                      "rpm_test_performed": bool(paths), "test_passed": True,
                      "installs_performed": False, "scripts_executed": False,
                      "installation_authorized": False, "storage_capacity_checked": False,
                      "freshness_proven": False}, sort_keys=True))
except (ValueError, KeyError, TypeError, OSError, UnicodeError, AttributeError) as error:
    print("azurelinux3s4: RPM compatibility deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
}

s4_check_updates() (
    command -v systemd-run >/dev/null && command -v rpmkeys >/dev/null || return 75
    local directory database evidence
    database=$(s4_rpm_database_path) || return 75
    directory=$(mktemp -d "$S4_RUN/update-check.XXXXXX") || return 75
    trap 'rm -rf -- "$directory"' EXIT
    s4_update_store plan >"$directory/plan.json" || return 75
    mkdir -m 0700 -- "$directory/packages" "$directory/home" || return 75
    timeout --kill-after=5s 1m python3 -I - "$directory/plan.json" >"$directory/files" <<'PY' || return 75
import json
import os
import sys
plan = json.load(open(sys.argv[1]))
for record in plan["packages"]:
    sys.stdout.buffer.write(os.fsencode(record["path"]) + b"\0")
PY
    local -a packages=()
    mapfile -d '' -t packages <"$directory/files"
    if (( ${#packages[@]} )); then
        local S4_ADMISSION_DESTINATION=$directory/packages
        s4_verify_rpm_artifacts "${packages[@]}" >"$directory/admission.json" || return 75
    else
        printf '{"schema":1,"vendor_fingerprint":"%s","artifacts":[],"installs_performed":false,"snapshots_retained":true,"freshness_proven":false}\n' \
            "$S4_VENDOR_FINGERPRINT" >"$directory/admission.json"
    fi
    s4_vendor_key_matches || return 75
    cp -- "$S4_GPG_KEY" "$directory/vendor.asc" || return 75
    chmod 0400 -- "$directory/vendor.asc" || return 75
    if (( ${#packages[@]} )); then
        chmod 0400 -- "$directory/packages/"*.rpm || return 75
    fi
    s4_rpm_test_program >"$directory/test.py" || return 75
    if timeout --signal=TERM --kill-after=30s 15m python3 -I - "$directory" "$database" "$S4_ARCH" <<'PY'
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
try:
    root = Path(sys.argv[1])
    unit = "azurelinux3s4-check-" + root.name.removeprefix("update-check.") + ".service"
    if any(character not in "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in str(root) + sys.argv[2]):
        raise ValueError("test workspace or database path is unsupported")
    command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + unit,
        "--property=RuntimeMaxSec=12min", "--property=TimeoutStopSec=15s", "--property=KillMode=control-group",
        "--property=ProtectSystem=strict", "--property=ReadWritePaths=" + str(root),
        "--property=ReadOnlyPaths=" + str(root / "packages") + " " + str(root / "vendor.asc") + " " + sys.argv[2],
        "--property=PrivateNetwork=yes", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
        "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectKernelLogs=yes",
        "--property=ProtectControlGroups=yes", "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
        "--property=LockPersonality=yes", "--property=UMask=0077", "--property=MemoryMax=768M",
        "--property=LimitFSIZE=1048576", "--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket",
        "--property=UnsetEnvironment=RPM_CONFIGDIR RPM_POPTEXEC_PATH LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH",
        "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
        "--setenv=HOME=" + str(root / "home"), "--", "python3", "-I", str(root / "test.py"), str(root), *sys.argv[2:]]
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    with (root / "native.log").open("xb") as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output, preexec_fn=limits)
        completed = False
        try:
            code = process.wait(timeout=750)
            completed = True
        finally:
            if not completed:
                stopped = subprocess.run(["systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                                         capture_output=True, timeout=30)
                process.kill()
                process.wait(timeout=15)
                if stopped.returncode:
                    raise ValueError("native test shutdown could not be confirmed")
    data = (root / "native.log").read_bytes()
    if code or not 0 < len(data) <= 1048576:
        print(data[:65536].decode("utf-8", "replace"), file=sys.stderr)
        raise ValueError("native RPM test did not provide bounded successful evidence")
    proof = json.loads(data)
    if (proof.get("schema") != 1 or proof.get("test_passed") is not True
            or any(proof.get(name) is not False for name in ("installs_performed", "scripts_executed", "installation_authorized", "storage_capacity_checked", "freshness_proven"))):
        raise ValueError("native test evidence is incomplete")
    (root / "result.json").write_text(json.dumps(proof, sort_keys=True) + "\n")
except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: update compatibility deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
    then
        evidence=$(cat -- "$directory/result.json") || return 75
    else
        return 75
    fi
    rm -rf -- "$directory" || return 75
    trap - EXIT
    s4_log 'Retained signed RPM batch passed its read-only transaction test; installation is unfinished.'
    printf '%s\n' "$evidence"
)

s4_verify_component() {
    case $1 in
        trust-anchor) s4_verify_trust_anchor ;;
        bootstrap) s4_verify_bootstrap ;;
        repository-trust) s4_verify_repository_trust ;;
        update-preparation) s4_update_store verify && s4_timer_state enabled active "$S4_UPDATE_TIMER" ;;
        update-compatibility) s4_check_updates ;;
        *) return 78 ;;
    esac
}

s4_tdnf_recovery() {
    # Never load a known-damaged plugin to repair that plugin. This narrowly
    # scoped bootstrap/recovery path retains TLS and RPM signature enforcement;
    # its first-fetch metadata limitation is reported before it is used.
    timeout --signal=TERM --kill-after=30s 15m \
        tdnf -c "$S4_STATE/tdnf.conf" --releasever=3.0 --refresh -y \
        --noplugins "$@" </dev/null
}

s4_verifier_damage() {
    # Check the registered runtime dependency closure before any plugin is loaded.
    # Queries and verification scripts must not execute package-supplied scripts.
    timeout --kill-after=5s 3m python3 -I - <<'PY'
import collections
import re
import stat
import subprocess
import sys

def rpm(*args):
    return subprocess.run(["rpm", *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=15)

try:
    pending = collections.deque(["tdnf-plugin-repogpgcheck", "tdnf", "gnupg2"])
    seen, providers, broken = set(), {}, set()
    while pending:
        package = pending.popleft()
        if package in seen:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}", package):
            raise ValueError("invalid RPM package identity")
        seen.add(package)
        if len(seen) > 128:
            raise ValueError("RPM dependency closure exceeds the verification bound")
        requirements = rpm("-q", "--requires", package)
        if requirements.returncode:
            raise ValueError("RPM requirements could not be queried for " + package)
        for requirement in requirements.stdout.splitlines():
            if requirement.startswith("rpmlib("):
                continue
            capability = requirement.split(" ", 1)[0]
            if capability not in providers:
                if len(providers) >= 1024:
                    raise ValueError("too many RPM dependency capabilities")
                result = rpm("-q", "--whatprovides", "--qf", "%{NAME}\n", capability)
                if result.returncode or not result.stdout.strip():
                    raise ValueError("RPM dependency has no installed provider: " + requirement)
                providers[capability] = result.stdout.splitlines()
            pending.extend(providers[capability])
        # rpm verification retains dependency/version checking as well as files.
        result = rpm("-V", "--noscripts", "--noconfig", package)
        if result.returncode == 0 and not result.stdout and not result.stderr:
            continue
        manifest = rpm("-q", "--qf", "[%{FILENAMES}\t%{FILEMODES}\t%{FILEFLAGS}\n]", package)
        if manifest.returncode:
            raise ValueError("RPM file manifest could not be queried for " + package)
        files = {}
        for entry in manifest.stdout.splitlines():
            name, mode, flags = entry.split("\t")
            files[name] = (int(mode), int(flags))
        def excluded(line):
            if " /" not in line:
                return False
            prefix, name = line.split(" /", 1)
            name = "/" + name
            if not re.fullmatch(r"(?:[.SM5DLUGTP?]{9}|missing)\s+[cdglr]?\s*", prefix):
                return False
            if name not in files:
                return False
            mode, flags = files[name]
            # RPM CONFIG/DOC/GHOST/LICENSE/README flags, directories, omitted
            # translations, and mutable logs/cache/runtime state are not code.
            # Critical write/executable ancestry is checked separately.
            return (bool(flags & (1 | 2 | 64 | 128 | 256)) or stat.S_ISDIR(mode)
                    or name.startswith(("/usr/share/locale/", "/var/log/", "/var/cache/", "/run/")))
        lines = result.stdout.splitlines()
        mutable_assets = (result.returncode == 1 and not result.stderr and bool(lines)
                          and all(excluded(line) for line in lines))
        if not mutable_assets:
            broken.add(package)
    for package in sorted(broken):
        print(package)
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: verifier integrity query failed: " + str(error), file=sys.stderr)
    sys.exit(1)
PY
}

s4_probe_verifier() {
    # No network, RPM transaction, global cache or imported test key is involved.
    # The control proves the fixture is readable; the enabled verifier must then
    # load through native tdnf and reject its deliberately invalid signature.
    timeout --kill-after=5s 90s python3 -I - "$S4_RUN" \
        "$S4_PLUGIN_LIBRARY" "$S4_PLUGIN_CONFIG" <<'PY'
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    with tempfile.TemporaryDirectory(prefix="verifier.", dir=sys.argv[1]) as directory:
        root = Path(directory)
        for name in ("repos", "sample/repodata", "control-cache", "check-cache", "persist", "gnupg"):
            (root / name).mkdir(parents=True, mode=0o700)
        # The repair service hides home directories. Use a private keyring with
        # no agent/keyserver startup, independent of the administrator's home.
        (root / "gnupg/gpg.conf").write_text(
            "no-autostart\ndisable-dirmngr\nno-auto-key-retrieve\nno-auto-key-import\n")
        environment = dict(os.environ, GNUPGHOME=str(root / "gnupg"), LC_ALL="C")
        metadata = b'<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"/>'
        primary = gzip.compress(metadata, mtime=0)
        (root / "sample/repodata/primary.xml.gz").write_bytes(primary)
        repomd = ('<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo">'
                  '<revision>0</revision><data type="primary"><checksum type="sha256">'
                  + hashlib.sha256(primary).hexdigest() + '</checksum><open-checksum type="sha256">'
                  + hashlib.sha256(metadata).hexdigest() + '</open-checksum>'
                  '<location href="repodata/primary.xml.gz"/><timestamp>0</timestamp><size>'
                  + str(len(primary)) + '</size><open-size>' + str(len(metadata))
                  + '</open-size></data></repomd>')
        (root / "sample/repodata/repomd.xml").write_text(repomd)
        (root / "sample/repodata/repomd.xml.asc").write_text("intentionally invalid signature\n")
        (root / "repos/probe.repo").write_text(
            "[azurelinux3s4-verifier-probe]\nname=Offline verifier probe\nbaseurl="
            + (root / "sample").as_uri()
            + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\nskip_if_unavailable=0\n")
        for name in ("control", "check"):
            (root / (name + ".conf")).write_text(
                "[main]\nplugins=1\ngpgcheck=1\nrepodir=" + str(root / "repos")
                + "\ncachedir=" + str(root / (name + "-cache"))
                + "\npersistdir=" + str(root / "persist")
                + "\npluginpath=" + str(Path(sys.argv[2]).parent)
                + "\npluginconfpath=" + str(Path(sys.argv[3]).parent) + "\n")
        def run(name, *options):
            return subprocess.run(["tdnf", "-v", "-c", str(root / (name + ".conf")),
                                   "--releasever=3.0", "--refresh", "-y", *options, "makecache"],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=25, env=environment)
        control = run("control", "--noplugins")
        check = run("check", "--disableplugin=*", "--enableplugin=tdnfrepogpgcheck")
        output = check.stdout + check.stderr
        if (control.returncode != 0 or check.returncode == 0
                or "Loaded plugin: tdnfrepogpgcheck" not in output
                or "gpg verify failed: No data" not in output
                or "Error: TDNFVerifySignature " not in output):
            print("azurelinux3s4: native metadata verifier did not prove fail-closed participation.",
                  file=sys.stderr)
            sys.exit(1)
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: bounded verifier probe failed: " + str(error), file=sys.stderr)
    sys.exit(1)
PY
}

s4_verify_metadata() {
    local damage tool executable library
    [[ -f $S4_PLUGIN_LIBRARY && ! -L $S4_PLUGIN_LIBRARY && -f $S4_PLUGIN_CONFIG ]] || return 1
    # Azure Linux's RPM-owned /usr/lib64 alias may resolve to /usr/lib.
    library=$(readlink -e -- "$S4_PLUGIN_LIBRARY") || return 1
    s4_safe_path "$library" || return 1
    s4_safe_path "$S4_PLUGIN_CONFIG" || return 1
    for tool in tdnf rpm python3 gpg2; do
        # Distro executable aliases (such as python3) may be RPM-owned symlinks.
        executable=$(readlink -e -- "$(command -v "$tool")") || return 1
        s4_safe_path "$executable" || return 1
        [[ -f $executable && -x $executable ]] || return 1
    done
    cmp -s -- "$S4_PLUGIN_CONFIG" <(printf '[main]\nenabled=1\n') || return 1
    damage=$(s4_verifier_damage) || return 1
    [[ -z $damage ]] || { s4_log "Damaged verifier runtime packages: $damage"; return 1; }
    s4_probe_verifier
}

s4_verify_bootstrap() {
    local package
    for package in "${S4_BOOTSTRAP_PACKAGES[@]}"; do
        rpm -q "$package" >/dev/null 2>&1 || return 1
    done
    command -v curl >/dev/null || return 1
    command -v python3 >/dev/null || return 1
    command -v update-ca-trust >/dev/null || return 1
    [[ -s $S4_CA_BUNDLE ]] || return 1
    openssl x509 -in "$S4_CA_BUNDLE" -noout >/dev/null 2>&1 || return 1
    s4_verify_metadata
}

s4_activate_verifier() {
    [[ -f $S4_PLUGIN_LIBRARY ]] || return 1
    s4_directory "$(dirname -- "$S4_PLUGIN_CONFIG")" 0755 || return $?
    s4_atomic_write "$S4_PLUGIN_CONFIG" 0644 <<'EOF'
[main]
enabled=1
EOF
}

s4_apply_bootstrap() {
    local package missing=no damage
    local -a damaged=()
    s4_repositories || return $?
    # Rebuild already-installed trust assets before HTTPS operations. A broken
    # RPM post-install hook must not be mistaken for a functional CA bundle.
    if command -v update-ca-trust >/dev/null; then
        update-ca-trust extract || return $?
    fi
    if [[ -f $S4_PLUGIN_LIBRARY ]]; then
        s4_activate_verifier || return $?
    fi
    for package in "${S4_BOOTSTRAP_PACKAGES[@]}"; do
        rpm -q "$package" >/dev/null 2>&1 || missing=yes
    done
    if [[ $missing == yes ]]; then
        s4_log 'Bootstrapping the verifier using TLS and distro-signed RPMs; first-fetch metadata trust remains limited.'
        s4_tdnf_recovery install "${S4_BOOTSTRAP_PACKAGES[@]}" || return $?
    fi
    damage=$(s4_verifier_damage) || return 75
    if [[ -n $damage ]]; then
        mapfile -t damaged <<<"$damage"
        s4_log 'Restoring damaged verifier payloads using TLS and distro-signed RPMs; recovery metadata trust remains limited.'
        s4_tdnf_recovery reinstall "${damaged[@]}" || return $?
    fi
    s4_activate_verifier || return $?
    update-ca-trust extract || return $?
    s4_verify_bootstrap
}

s4_run_component() {
    bash "$S4_INSTALL_DIR/azurelinux3s4.sh" --component "$1"
}

s4_defer_component() {
    local component=$1 result=$2 attempts=$3 delay next
    (( attempts >= 1 && attempts <= 11 )) || attempts=11
    delay=$((60 * (1 << (attempts - 1))))
    (( delay <= 3600 )) || delay=3600
    next=$((S4_NOW + delay + RANDOM % 31))
    s4_write_state "$component" pending "$attempts" "$next" "$result" || return $?
    s4_log "$component failed (exit $result); automatic repair remains enabled."
    return 75
}

s4_reconcile_component() {
    local component=$1 force=$2 attempts next result
    [[ $component == trust-anchor || $component == bootstrap || $component == repository-trust || $component == update-preparation || $component == update-compatibility ]] || return 78
    if [[ $component == repository-trust || $component == update-preparation || $component == update-compatibility ]]; then
        # Always obtain fresh online/preparation/transaction-test evidence.
        # Honor backoff before work and do not repeat a failed operation in a child.
        attempts=$(s4_state_value "$component" attempts)
        next=$(s4_state_value "$component" next_attempt)
        (( next <= S4_NOW + 3630 )) || next=0
        if [[ $force != yes ]] && (( next > S4_NOW )); then
            s4_log "$component is pending; next permitted attempt is $next."
            return 75
        fi
        (( attempts < 10 )) || attempts=10
        attempts=$((attempts + 1))
        s4_write_state "$component" running "$attempts" 0 0 || return $?
        result=0
        case $component in
            repository-trust) s4_verify_repository_trust || result=$? ;;
            update-preparation)
                if s4_start_timer "$S4_UPDATE_TIMER"; then
                    s4_prepare_updates || result=$?
                else
                    result=$?
                fi ;;
            update-compatibility) s4_check_updates || result=$? ;;
        esac
        if (( result == 0 )); then
            s4_write_state "$component" complete 0 0 0
            return $?
        fi
        s4_defer_component "$component" "$result" "$attempts"
        return $?
    fi
    if s4_verify_component "$component"; then
        # A stale success marker alone never proves completion.
        s4_write_state "$component" complete 0 0 0
        return $?
    fi
    attempts=$(s4_state_value "$component" attempts)
    next=$(s4_state_value "$component" next_attempt)
    # A backwards clock correction must not strand work for months or years.
    (( next <= S4_NOW + 3630 )) || next=0
    if [[ $force != yes ]] && (( next > S4_NOW )); then
        s4_log "$component is pending; next permitted attempt is $next."
        return 75
    fi
    # Cap attempts before arithmetic, including after corrupted or edited state.
    (( attempts < 10 )) || attempts=10
    attempts=$((attempts + 1))
    s4_write_state "$component" running "$attempts" 0 0 || return $?
    result=0
    # Run in a new shell with errexit enabled even when the caller uses `if`.
    # Do not let Bash's conditional-function errexit exception mask a failed step.
    if s4_run_component "$component"; then
        if s4_verify_component "$component"; then
            s4_write_state "$component" complete 0 0 0
            return $?
        fi
        result=1
    else
        result=$?
    fi
    s4_defer_component "$component" "$result" "$attempts"
}

s4_install_runner() {
    local source=${BASH_SOURCE[0]}
    s4_directory "$S4_INSTALL_DIR" 0755 || return $?
    s4_atomic_write "$S4_INSTALL_DIR/azurelinux3s4.sh" 0755 <"$source"
}

s4_repair_timeout_seconds() {
    # Sum the complete current repair path, not just the download. Include each
    # leaf timeout's kill grace; nested work is already covered by its outer cap.
    local key=$((15 + 5)) control=$((30 + 5))
    local integrity=$((180 + 5)) participation=$((90 + 5))
    local recovery=$((900 + 30)) refresh=$((300 + 30)) download=$((900 + 30))
    local store=$((300 + 5)) admission=$((900 + 5))
    # Trust can fail verification, apply, then pass both child and parent checks:
    # three complete admissions, plus apply's queries/import/key publication.
    local trust=$((3 * (2 * key + 5 * control) + 5 * control + key))
    # Bootstrap: initial, child final, parent final; repository and download:
    # two further full health checks. Bootstrap also inspects damage separately.
    local health=$((5 * (integrity + participation) + integrity))
    # Up to two recovery transactions (install + reinstall), one signed refresh,
    # one download, and begin/list/commit store operations, followed by admission.
    local compatibility=$((2 * control + key + store + 65 + admission + 930))
    local stages=$((2 * recovery + refresh + download + 3 * store + admission + compatibility))
    # At most 34 state/repository/plugin/timer persistence/control calls on the
    # successful repair branch; reserve 40 to include restoration after failure.
    # Another ten minutes cover trusted local tools, file fsync, cleanup and
    # scheduling outside leaf wrappers. Excessive IO still fails finitely and
    # retains retry ownership; this is not a promise for arbitrary slow storage.
    # Compatibility adds component state writes; four more reserved controls.
    local housekeeping=$((44 * control + 600))
    printf '%s\n' "$((trust + health + stages + housekeeping))"
}

s4_install_units() {
    local deadline
    deadline=$(s4_repair_timeout_seconds) || return $?
    s4_safe_path "$S4_SYSTEMD_DIR" || return $?
    s4_atomic_write "$S4_SYSTEMD_DIR/azurelinux3s4-repair.service" 0644 <<EOF || return $?
[Unit]
Description=Retry incomplete Azure Linux 3 server setup components
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $S4_INSTALL_DIR/azurelinux3s4.sh --repair
TimeoutStartSec=${deadline}s
TimeoutStopSec=30s
KillMode=control-group
UMask=0077
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=azurelinux3s4
EOF
    s4_atomic_write "$S4_SYSTEMD_DIR/azurelinux3s4-repair.timer" 0644 <<'EOF' || return $?
[Unit]
Description=Retry deferred Azure Linux 3 server setup

[Timer]
OnBootSec=2min
OnUnitInactiveSec=1min
RandomizedDelaySec=30s
AccuracySec=10s
Unit=azurelinux3s4-repair.service

[Install]
WantedBy=timers.target
EOF
    s4_atomic_write "$S4_SYSTEMD_DIR/$S4_RECOVERY_TIMER" 0644 <<'EOF' || return $?
[Unit]
Description=Recover interrupted Azure Linux 3 setup finalization

[Timer]
OnBootSec=1min
OnActiveSec=1min
OnUnitInactiveSec=1min
RandomizedDelaySec=10s
AccuracySec=5s
Unit=azurelinux3s4-repair.service

[Install]
WantedBy=timers.target
EOF
    s4_atomic_write "$S4_SYSTEMD_DIR/$S4_UPDATE_TIMER" 0644 <<'EOF' || return $?
[Unit]
Description=Periodically prepare vendor-signed Azure Linux 3 updates

[Timer]
OnBootSec=3min
OnCalendar=hourly
Persistent=yes
RandomizedDelaySec=15min
AccuracySec=1min
Unit=azurelinux3s4-repair.service

[Install]
WantedBy=timers.target
EOF
    # OnBootSec makes an offline reboot resume work; no network-online gate stalls
    # timer installation. Failed one-shots remain eligible for the next attempt.
    timeout --kill-after=5s 30s systemctl daemon-reload || return $?
    s4_start_repair_timer || return $?
    s4_start_timer "$S4_UPDATE_TIMER"
}

s4_timer_state() {
    local enabled=$1 active=$2 unit=${3:-$S4_REPAIR_TIMER} observed
    observed=$(timeout --kill-after=5s 30s systemctl show --no-pager \
        --property=LoadState,UnitFileState,ActiveState "$unit") || return 1
    # A query error or an unexpected state is never evidence of completion.
    # enabled-runtime does not establish persistence across reboot.
    awk -F= -v enabled="$enabled" -v active="$active" '
        NF != 2 { bad=1 }
        $1 == "LoadState" { loads++; if ($2 != "loaded") bad=1 }
        $1 == "UnitFileState" { files++; if ($2 != enabled) bad=1 }
        $1 == "ActiveState" { states++; if ($2 != active) bad=1 }
        END { exit !(loads == 1 && files == 1 && states == 1 && !bad) }
    ' <<<"$observed"
}

s4_preserve_retry_link() {
    local unit=${1:-$S4_REPAIR_TIMER} directory=$S4_SYSTEMD_DIR/timers.target.wants link target
    [[ $unit == "$S4_REPAIR_TIMER" || $unit == "$S4_RECOVERY_TIMER" || $unit == "$S4_UPDATE_TIMER" ]] || return 78
    target=$S4_SYSTEMD_DIR/$unit
    link=$directory/$unit
    s4_safe_path "$target" || return $?
    [[ -f $target ]] || return 78
    s4_directory "$directory" 0755 || return $?
    if [[ -L $link ]]; then
        [[ $(readlink -f -- "$link") == "$target" ]] || return 78
    else
        [[ ! -e $link ]] || return 78
        ln -s -- "$target" "$link" || return $?
    fi
    # Visibility is not durability, including on a repeated recovery attempt.
    # syncfs covers the link and newly created ancestry on their filesystems.
    timeout --kill-after=5s 30s sync -f -- "$directory" "$S4_SYSTEMD_DIR" || return $?
    [[ -L $link && $(readlink -f -- "$link") == "$target" ]]
}

s4_start_timer() {
    local unit=$1
    # Retain a checked boot activation link even when the manager is unavailable
    # or a failed disable operation removed the previous link before failing.
    s4_preserve_retry_link "$unit" || return $?
    timeout --kill-after=5s 30s systemctl enable --now "$unit" || return $?
    s4_preserve_retry_link "$unit" || return $?
    s4_timer_state enabled active "$unit"
}

s4_start_repair_timer() {
    s4_start_timer "$S4_REPAIR_TIMER"
}

s4_arm_finalization_recovery() {
    local path
    # These may reside on different filesystems. Flush executable/unit payloads
    # and their ancestry before relying on a boot activation link.
    for path in "$S4_INSTALL_DIR/azurelinux3s4.sh" \
                "$S4_SYSTEMD_DIR/azurelinux3s4-repair.service" \
                "$S4_SYSTEMD_DIR/$S4_RECOVERY_TIMER"; do
        s4_safe_path "$path" || return $?
        [[ -f $path ]] || return 78
    done
    timeout --kill-after=5s 30s sync -f -- "$S4_INSTALL_DIR" "$S4_SYSTEMD_DIR" "$S4_STATE" || return $?
    s4_start_timer "$S4_RECOVERY_TIMER"
}

s4_stop_timer() {
    local unit=$1 directory=$S4_SYSTEMD_DIR/timers.target.wants link
    [[ $unit == "$S4_REPAIR_TIMER" || $unit == "$S4_RECOVERY_TIMER" ]] || return 78
    link=$directory/$unit
    s4_safe_path "$directory" || return $?
    # Do not let systemctl remove an operator's wrong-kind or foreign object.
    if [[ -L $link ]]; then
        [[ $(readlink -f -- "$link") == "$S4_SYSTEMD_DIR/$unit" ]] || return 78
    else
        [[ ! -e $link ]] || return 78
    fi
    timeout --kill-after=5s 30s systemctl disable --now "$unit" || return $?
    s4_timer_state disabled inactive "$unit" || return 1
    [[ ! -e $link && ! -L $link ]] || return 1
    if [[ -d $directory ]]; then
        timeout --kill-after=5s 30s sync -f -- "$directory" "$S4_SYSTEMD_DIR" || return $?
    else
        # systemctl may remove the empty wants directory along with its last link.
        timeout --kill-after=5s 30s sync -f -- "$S4_SYSTEMD_DIR" || return $?
    fi
    [[ ! -e $link && ! -L $link ]]
}

s4_finish_repair() {
    local result=0
    # Keep the original boot activation until independent recovery is durable
    # and positively observed active. Never remove the last pending activator.
    s4_preserve_retry_link || return 75
    if ! printf 'status=pending\n' | s4_atomic_write "$S4_STATE/finalization" 0600; then
        s4_restore_repair_timer
        return 75
    fi
    if ! s4_arm_finalization_recovery; then
        s4_log 'Independent finalization recovery could not be verified; keeping automatic repair.'
        s4_restore_repair_timer
        return 75
    fi
    if s4_stop_timer "$S4_REPAIR_TIMER"; then
        if printf 'status=complete\n' | s4_atomic_write "$S4_STATE/finalization" 0600; then
            # Recovery intent is the independent boot link. Retire it only after
            # completion is durable. A crash before this cleanup re-runs the same
            # locked, health-checking worker and finishes cleanup automatically.
            if s4_stop_timer "$S4_RECOVERY_TIMER"; then
                s4_log 'Bootstrap verified; its repair timer has stopped. Finalization recovery has stopped.'
                return 0
            fi
            s4_log 'Completion is durable; finalization recovery timer cleanup remains pending.'
            s4_restore_repair_timer "$S4_RECOVERY_TIMER"
            return 75
        fi
        result=1
    else
        result=$?
    fi
    s4_log "Timer finalization is pending (exit $result); restoring automatic repair."
    s4_restore_repair_timer
    return 75
}

s4_restore_repair_timer() {
    local unit=${1:-$S4_REPAIR_TIMER}
    if ! s4_start_timer "$unit"; then
        if s4_preserve_retry_link "$unit"; then
            s4_log "Boot retry activation is verified for $unit; runtime activation could not be verified."
        else
            s4_log 'Automatic retry activation could not be preserved.'
        fi
    fi
}

s4_repair() {
    local force=$1 component pending=no result attempts
    S4_NOW=$(date +%s)
    if [[ ${S4_COMPONENTS[0]} == trust-anchor ]] && ! s4_reconcile_component trust-anchor "$force"; then
        pending=yes
    elif s4_repositories; then
        for component in "${S4_COMPONENTS[@]}"; do
            [[ $component != trust-anchor ]] || continue
            if ! s4_reconcile_component "$component" "$force"; then
                pending=yes
            fi
        done
    else
        result=$?
        pending=yes
        for component in "${S4_COMPONENTS[@]}"; do
            [[ $component != trust-anchor ]] || continue
            attempts=$(s4_state_value "$component" attempts)
            (( attempts < 10 )) || attempts=10
            s4_defer_component "$component" "$result" "$((attempts + 1))" || true
        done
    fi
    if [[ $pending == yes ]]; then
        # Repair missing timer activation as well as missing packages.
        s4_start_repair_timer || return 75
        s4_log 'Setup components remain pending; automatic repair will continue.'
        return 75
    fi
    s4_finish_repair
}

s4_status() {
    printf 'version=%s\nserver_ready=no\nimplemented_components=%s\n' "$S4_VERSION" "${S4_COMPONENTS[*]}"
    local component
    for component in "${S4_COMPONENTS[@]}"; do
        printf '\n[%s]\n' "$component"
        if [[ -f $S4_STATE/components/$component ]]; then
            cat -- "$S4_STATE/components/$component"
        else
            printf 'status=not-installed\n'
        fi
    done
    if [[ -f $S4_STATE/finalization ]]; then
        printf '\n[timer_finalization]\n'
        cat -- "$S4_STATE/finalization"
    fi
    printf '\nRemaining: network containment, dedicated SSH admin, host/service hardening, nginx/HTTPS, .NET, automatic updates/reboots.\n'
}

s4_main() {
    # Ignore caller-supplied tool paths and language/runtime startup configuration.
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    unset BASH_ENV ENV CDPATH PYTHONPATH
    umask 077
    local action=${1:-install}
    case $action in
        --help)
            printf 'Usage: sudo ./azurelinux3s4.sh\n       sudo ./azurelinux3s4.sh --status\nDevelopment checkpoint: signed-update preparation and read-only RPM transaction tests; server hardening and update installation are incomplete.\n'
            return 0 ;;
        install|--status|--repair|--prepare-updates|--check-updates) [[ $# -le 1 ]] || return 64 ;;
        --verify-rpm) (( $# >= 2 && $# <= 129 )) || return 64 ;;
        --component) [[ $# == 2 && ( $2 == trust-anchor || $2 == bootstrap || $2 == repository-trust || $2 == update-preparation || $2 == update-compatibility ) ]] || return 64 ;;
        *) s4_log 'Unknown argument. Use --help.'; return 64 ;;
    esac
    s4_preflight || return $?
    if [[ $action == --status ]]; then
        s4_status
        return 0
    fi
    s4_prepare_state || return $?
    s4_lock || return $?
    if [[ $action == --verify-rpm ]]; then
        shift
        s4_verify_rpm_artifacts "$@"
        return $?
    fi
    if [[ $action == --prepare-updates ]]; then
        s4_verify_trust_anchor && s4_repositories && s4_verify_bootstrap || return 75
        s4_prepare_updates
        return $?
    fi
    if [[ $action == --check-updates ]]; then
        s4_verify_trust_anchor || return 75
        s4_check_updates
        return $?
    fi
    if [[ $action == --component ]]; then
        case $2 in
            trust-anchor) s4_apply_trust_anchor ;;
            bootstrap) s4_apply_bootstrap ;;
            repository-trust) s4_verify_repository_trust ;;
            update-preparation) s4_prepare_updates ;;
            update-compatibility) s4_check_updates ;;
        esac
        return $?
    fi
    if [[ $action == install ]]; then
        s4_install_runner || return $?
        s4_install_units || return $?
        s4_repair yes || return $?
        s4_log 'INCOMPLETE: trust, preparation and read-only update tests only. Host hardening and automatic package installation remain unfinished.'
        return 78
    fi
    s4_repair no
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    s4_main "$@"
fi

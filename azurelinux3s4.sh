#!/bin/bash
# Azure Linux 3 Safe SSH Server Set-up. This checkpoint is a bootstrap foundation.
# Full host/network/SSH/web/runtime hardening is deliberately not reported ready.

set -Eeuo pipefail

S4_VERSION=0.25.0
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
S4_COMPONENTS=(trust-anchor bootstrap repository-trust update-preparation update-compatibility update-capacity update-effects update-interpreters update-removals)
S4_UPDATE_TIMER=azurelinux3s4-update-preparation.timer
# Internal dynamic-scope options; never accept inherited environment values.
S4_ADMISSION_DESTINATION=
S4_DOWNLOAD_DIRECTORY=
S4_CAPACITY_MODE=
S4_EFFECTS_MODE=
S4_INTERPRETERS_MODE=
S4_REMOVALS_MODE=
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

s4_rpm_effects_program() {
    # Decode bounded native exports, never evaluate script text or macros.
    # This inventory does not predict trigger selection or approve execution.
    cat <<'PY'
import hashlib
import struct

EFFECT_TAGS = {}
for name, body, program, flags in (
    ("prein", 1023, 1085, 5020), ("postin", 1024, 1086, 5021),
    ("preun", 1025, 1087, 5022), ("postun", 1026, 1088, 5023),
    ("pretrans", 1151, 1153, 5024), ("posttrans", 1152, 1154, 5025),
    ("verify", 1079, 1091, 5026),
):
    EFFECT_TAGS.update({body: (name + "_body", 6, False),
                        program: (name + "_program", 8, True),
                        flags: (name + "_flags", 4, True)})
for name, body, program, flags, names, versions, senses, indexes, priority in (
    ("trigger", 1065, 1092, 5027, 1066, 1067, 1068, 1069, None),
    ("filetrigger", 5066, 5067, 5068, 5069, 5071, 5072, 5070, 5084),
    ("transfiletrigger", 5076, 5077, 5078, 5079, 5081, 5082, 5080, 5085),
):
    EFFECT_TAGS.update({body: (name + "_bodies", 8, False),
                        program: (name + "_programs", 8, True),
                        flags: (name + "_script_flags", 4, True),
                        names: (name + "_names", 8, False),
                        versions: (name + "_versions", 8, False),
                        senses: (name + "_senses", 4, True),
                        indexes: (name + "_indexes", 4, True)})
    if priority:
        EFFECT_TAGS[priority] = (name + "_priorities", 4, True)

def audit_header(material):
    # headerExport: two network-order uint32 sizes, 16-byte indexes, data.
    if not 8 <= len(material) <= 8 * 1024 * 1024:
        raise ValueError("effects header export exceeds its bound")
    entries, size = struct.unpack_from(">II", material)
    if not 0 < entries <= 65536 or 8 + 16 * entries + size != len(material):
        raise ValueError("effects header export layout is inconsistent")
    start, seen, tags = 8 + 16 * entries, set(), []
    for index in range(entries):
        tag, kind, offset, count = struct.unpack_from(">IIII", material, 8 + 16 * index)
        if tag not in EFFECT_TAGS:
            continue
        label, expected, disclose = EFFECT_TAGS[tag]
        scalar = tag in (1023, 1024, 1025, 1026, 1079, 1151, 1152,
                         5020, 5021, 5022, 5023, 5024, 5025, 5026)
        # RPM's HEADERGET_ARGV also accepts an ordinary interpreter encoded
        # as one scalar string. Genuine Azure headers commonly use this form.
        legacy_program = tag in (1085, 1086, 1087, 1088, 1091, 1153, 1154) and kind == 6 and count == 1
        if (tag in seen or (kind != expected and not legacy_program) or not 0 < count <= 4096
                or (scalar and count != 1) or offset >= size):
            raise ValueError("effects tag type/count/identity is unsupported: " + str(tag))
        seen.add(tag)
        cursor, values = start + offset, []
        if kind == 4:
            end = cursor + 4 * count
            if offset % 4 or end > len(material):
                raise ValueError("effects integer array exceeds the header")
            values = list(struct.unpack_from(">" + "I" * count, material, cursor))
            cursor = end
        else:
            for _ in range(count):
                end = material.find(b"\0", cursor)
                limit = 4096 if disclose else 1024 * 1024
                if end < cursor or end - cursor > limit:
                    raise ValueError("effects string is unterminated or excessive")
                value = material[cursor:end]
                values.append(value.decode("utf-8") if disclose else {
                    "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()})
                cursor = end + 1
        encoded = material[start + offset:cursor]
        tags.append({"tag": tag, "name": label, "type": kind, "count": count,
                     "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest(), "values": values})
    return {"header_bytes": len(material), "header_sha256": hashlib.sha256(material).hexdigest(),
            "tags": sorted(tags, key=lambda value: value["tag"])}
PY
}

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
    if sys.argv[4:] not in ([], ["capacity"], ["effects"]):
        raise ValueError("unsupported RPM diagnostic mode")
    capacity, effects = sys.argv[4:] == ["capacity"], sys.argv[4:] == ["effects"]
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
    if effects:
        api["rpmteDBInstance"] = bind("rpmteDBInstance", unsigned, pointer)
        api["headerGetAsString"] = bind("headerGetAsString", pointer, pointer, integer)
    if capacity:
        extra = {
            "rpmfiNew": (pointer, pointer, pointer, integer, unsigned),
            "rpmfiFree": (pointer, pointer), "rpmfiInit": (pointer, pointer, integer),
            "rpmfiNext": (integer, pointer), "rpmfiFC": (unsigned, pointer),
            "rpmfiFN": (string, pointer), "rpmfiFSize": (C.c_uint64, pointer),
            "rpmfiFMode": (C.c_uint16, pointer), "rpmfiFFlags": (unsigned, pointer),
            "rpmfiFLink": (string, pointer),
            "headerGet": (integer, pointer, integer, pointer, unsigned),
            "rpmtdNew": (pointer,), "rpmtdFree": (pointer, pointer),
            "rpmtdFreeData": (None, pointer), "rpmtdCount": (unsigned, pointer),
            "rpmtdType": (integer, pointer),
        }
        api.update({name: bind(name, *signature) for name, signature in extra.items()})
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
    def effect_identity(header):
        name, identity = api["headerGetString"](header, 1000), None
        material = api["headerGetAsString"](header, 5016)
        try:
            if material:
                identity = C.string_at(material)
            if (not name or not re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", name)
                    or not identity or not 0 < len(identity) <= 1024
                    or any(value < 33 or value > 126 for value in identity)):
                raise ValueError("effects package identity is unsupported")
            return {"name": name.decode("ascii"), "nevra": identity.decode("ascii")}
        finally:
            if material:
                libc.free(material)
    effects_bytes, signed_header_bytes = 0, 0
    def observe_effects(header, exported):
        global effects_bytes
        value = {**effect_identity(header), **audit_header(exported)}
        effects_bytes += len(json.dumps(value, sort_keys=True).encode("utf-8"))
        # Retain at most 16MiB of metadata before plan/removal duplication;
        # the final 32MiB output cap is separate and positively checked.
        if effects_bytes > 16 * 1024 * 1024:
            raise ValueError("effects observations exceed their aggregate bound")
        return value
    def baseline(observations=None):
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
                    instance = api["rpmdbGetIteratorOffset"](iterator)
                    exported = C.string_at(material, size.value)
                    entries.append((instance, hashlib.sha256(exported).hexdigest()))
                    if observations is not None:
                        if not instance or instance in observations:
                            raise ValueError("effects installed instance is missing or duplicated")
                        observations[instance] = {"instance": instance, **observe_effects(header, exported)}
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
    installed_effects, incoming_effects, removal_effects, removed_instances = {}, [], [], set()
    before = baseline(installed_effects if effects else None)
    ts = transaction()
    install_only = {b"kernel", b"kernel-mshv", b"kernel-uvm", b"kernel-uki", b"kernel-64k", b"kernel-hwe"}
    additions, removals = [], []
    pretrans = {}
    inventory, file_total, header_total, payload_total = [], 0, 0, 0
    def tag_info(header, tag):
        td = api["rpmtdNew"]()
        if not td:
            raise ValueError("signed file tag allocation failed")
        try:
            present = api["headerGet"](header, tag, td, 0)
            if present not in (0, 1):
                raise ValueError("signed file tag observation failed")
            return (api["rpmtdType"](td), api["rpmtdCount"](td)) if present else None
        finally:
            api["rpmtdFreeData"](td)
            api["rpmtdFree"](td)
    def payload(header, index):
        global file_total, header_total, payload_total
        fi, material = None, None
        try:
            names = tag_info(header, 1117)  # BASENAMES, string array.
            if names is None:
                if tag_info(header, 1027) is not None:
                    raise ValueError("obsolete signed file paths are unsupported")
                count = 0
            else:
                if names[0] != 8:
                    raise ValueError("signed basename array type is invalid")
                count = names[1]
            file_total += count
            if file_total > 131072:
                raise ValueError("signed file inventory exceeds its count bound")
            # rpmfi otherwise silently defaults missing attributes to zero;
            # validate types/counts BEFORE its C iterator indexes those arrays.
            short, long = tag_info(header, 1028), tag_info(header, 5008)
            arrays = [(tag_info(header, 1030), 3), (tag_info(header, 1037), 4)]
            if short is not None:
                arrays.append((short, 4))
            if long is not None:
                arrays.append((long, 5))
            if count and short is None and long is None:
                raise ValueError("signed file size array is missing")
            for entry, kind in arrays:
                if (count and entry != (kind, count)) or (entry is not None and entry != (kind, count)):
                    raise ValueError("signed file attribute array type/count differs")
            links = tag_info(header, 1036)
            if links is not None and links != (8, count):
                raise ValueError("signed symlink array type/count differs")
            # Load only sizes/modes/flags/links and the validated path triplet.
            # The earlier independent cryptographic admission and native TEST
            # continue to verify signatures/digests; this is inventory control.
            fi_flags = ((1 << 20) - 2) & ~((1 << 6) | (1 << 7) | (1 << 9) | (1 << 17))
            fi = api["rpmfiNew"](ts, header, 0, fi_flags)
            if not fi or api["rpmfiFC"](fi) != count or not api["rpmfiInit"](fi, 0):
                raise ValueError("signed file inventory could not be loaded consistently")
            size = unsigned()
            material = api["headerExport"](header, C.byref(size))
            header_total += size.value
            if not material or not 0 < size.value <= 8 * 1024 * 1024 or header_total > 64 * 1024 * 1024:
                raise ValueError("signed header inventory exceeds its bound")
            files, seen = [], set()
            for expected in range(count):
                if api["rpmfiNext"](fi) != expected:
                    raise ValueError("signed file inventory ended or changed unexpectedly")
                name, link = api["rpmfiFN"](fi), api["rpmfiFLink"](fi)
                length, mode, flags = api["rpmfiFSize"](fi), api["rpmfiFMode"](fi), api["rpmfiFFlags"](fi)
                if not name or len(name) > 4096 or name in seen or length > 16 * 1024 ** 3:
                    raise ValueError("signed file metadata is missing, duplicated or excessive")
                if stat.S_ISLNK(mode) and (links is None or not link):
                    raise ValueError("signed symlink target is missing")
                seen.add(name)
                payload_total += length
                if payload_total > 64 * 1024 ** 3:
                    raise ValueError("expanded signed payload exceeds its bound")
                files.append({"path": name.decode("utf-8"), "bytes": length, "mode": mode,
                              "flags": flags, "link": link.decode("utf-8") if link else ""})
            if api["rpmfiNext"](fi) != -1:
                raise ValueError("signed file inventory has unexpected trailing entries")
            inventory.append({"file": records[index]["file"], "sha256": records[index]["sha256"],
                              "bytes": records[index]["bytes"], "header_bytes": size.value, "files": files})
        finally:
            if material:
                libc.free(material)
            if fi:
                api["rpmfiFree"](fi)
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
        for index, path in enumerate(paths):
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
                if capacity:
                    payload(header, index)
                if effects:
                    size = unsigned()
                    exported = api["headerExport"](header, C.byref(size))
                    try:
                        if not exported or not 0 < size.value <= 8 * 1024 * 1024:
                            raise ValueError("effects signed header export exceeds its bound")
                        signed_header_bytes += size.value
                        if signed_header_bytes > 64 * 1024 * 1024:
                            raise ValueError("effects signed headers exceed their aggregate bound")
                        incoming_effects.append({"file": records[index]["file"],
                            "sha256": records[index]["sha256"], "bytes": records[index]["bytes"],
                            **observe_effects(header, C.string_at(exported, size.value))})
                    finally:
                        if exported:
                            libc.free(exported)
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
                if effects:
                    instance = api["rpmteDBInstance"](element)
                    observed = installed_effects.get(instance)
                    if (not observed or observed["nevra"] != identity.decode("ascii")
                            or observed["name"].encode("ascii") != name
                            or instance in removed_instances):
                        raise ValueError("native removal differs from the observed installed instance")
                    removed_instances.add(instance)
                    removal_effects.append({**observed, "classification": "same-name-replacement"
                        if any(value["name"] == observed["name"] for value in incoming_effects)
                        else "other-removal"})
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
    proof = {"schema": 1, "manifest_sha256": plan["manifest_sha256"],
                      "baseline": before, "additions": additions, "removals": removals,
                      "rpm_test_performed": bool(paths), "test_passed": True,
                      "installs_performed": False, "scripts_executed": False,
                      "installation_authorized": False, "storage_capacity_checked": False,
                      "freshness_proven": False}
    if capacity:
        data = json.dumps({"schema": 1, "manifest_sha256": plan["manifest_sha256"],
                           "artifacts": inventory}, sort_keys=True).encode("utf-8")
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("signed file inventory exceeds its output bound")
        with (root / "inventory.json").open("xb") as output:
            output.write(data)
        proof["payload_inventory"] = {"sha256": hashlib.sha256(data).hexdigest(),
                                      "bytes": len(data), "files": file_total}
    if effects:
        binding = lambda value: (value["file"], value["sha256"], value["bytes"], value["nevra"])
        if sorted(map(binding, incoming_effects)) != sorted(map(binding, additions)):
            raise ValueError("native additions differ from the observed admitted header identities")
        proof["effects"] = {"schema": 1, "incoming": incoming_effects, "removals": removal_effects,
            "installed_script_owners": [value for _, value in sorted(installed_effects.items()) if value["tags"]],
            "installed_headers_observed": before["headers"], "script_metadata_observed": True,
            "removals_bound_to_installed_instances": True, "installed_headers_authenticated": False,
            "trigger_selection_complete": False, "script_execution_plan_complete": False,
            "script_policy_satisfied": False, "removal_policy_satisfied": False,
            "rollback_policy_satisfied": False}
    data = json.dumps(proof, sort_keys=True)
    if effects and len(data.encode("utf-8")) > 32 * 1024 * 1024:
        raise ValueError("effects report exceeds its output bound")
    print(data)
except (ValueError, KeyError, TypeError, OSError, UnicodeError, AttributeError) as error:
    print("azurelinux3s4: RPM compatibility deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
}

s4_update_capacity_program() {
    # Observe advertised capacity only; scripts/rollback and reservation remain unproved.
    cat <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import sys

def private(path, limit):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 < before.st_size <= limit):
        raise ValueError("capacity input is not a bounded private regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("capacity input changed before opening")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if ((after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns) or len(data) != before.st_size):
        raise ValueError("capacity input changed during reading")
    return data

def pathname(value):
    if (not isinstance(value, str) or not value.startswith("/") or "//" in value
            or len(value.encode("utf-8")) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or (value != "/" and value.endswith("/"))
            or any(part in (".", "..") for part in value.split("/"))):
        raise ValueError("signed destination path is not canonical")
    return value

def trusted(observed):
    if observed.st_uid not in (0, os.geteuid()) or observed.st_mode & 0o022:
        raise ValueError("capacity destination has untrusted writable ancestry")

def identity(observed):
    return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid)

def mount_id(fd):
    entries = re.findall(r"^mnt_id:\s*([0-9]+)$", Path(f"/proc/self/fdinfo/{fd}").read_text(), re.M)
    if len(entries) != 1:
        raise ValueError("descriptor mount identity could not be observed")
    return int(entries[0])

def dir_open(name, fd=None):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                   dir_fd=fd)

held = []
try:
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (240, 245))
    _, descriptor_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    descriptor_limit = min(256, descriptor_hard) if descriptor_hard > 0 else 256
    resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, descriptor_hard))
    workspace, database = Path(sys.argv[1]), pathname(sys.argv[2])
    proof = json.loads(private(workspace / "result.json", 1024 * 1024))
    data = private(workspace / "inventory.json", 32 * 1024 * 1024)
    inventory = json.loads(data)
    receipt = proof["payload_inventory"]
    if (proof.get("test_passed") is not True or proof.get("installation_authorized") is not False
            or receipt.get("sha256") != hashlib.sha256(data).hexdigest() or receipt.get("bytes") != len(data)
            or set(inventory) != {"schema", "manifest_sha256", "artifacts"} or inventory["schema"] != 1
            or inventory["manifest_sha256"] != proof["manifest_sha256"]
            or not isinstance(inventory["artifacts"], list) or len(inventory["artifacts"]) > 128):
        raise ValueError("capacity inventory is not bound to the successful same-byte TEST")
    expected = {item["file"]: (item["sha256"], item["bytes"]) for item in proof["additions"]}
    if len(expected) != len(proof["additions"]) or len(expected) != len(inventory["artifacts"]):
        raise ValueError("capacity inventory batch count differs")
    files, header_bytes, payload_bytes, seen_packages, types = [], 0, 0, set(), {}
    for package in inventory["artifacts"]:
        if (set(package) != {"file", "sha256", "bytes", "header_bytes", "files"}
                or package["file"] in seen_packages
                or expected.get(package["file"]) != (package["sha256"], package["bytes"])
                or type(package["header_bytes"]) is not int or not 0 < package["header_bytes"] <= 8 * 1024 * 1024
                or not isinstance(package["files"], list)):
            raise ValueError("capacity inventory does not preserve the admitted package identity")
        seen_packages.add(package["file"])
        header_bytes += package["header_bytes"]
        seen_paths = set()
        for entry in package["files"]:
            if (set(entry) != {"path", "bytes", "mode", "flags", "link"}
                    or type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= 16 * 1024 ** 3
                    or type(entry["mode"]) is not int or not 0 <= entry["mode"] <= 65535
                    or type(entry["flags"]) is not int or not 0 <= entry["flags"] < 2 ** 32
                    or not isinstance(entry["link"], str) or len(entry["link"].encode("utf-8")) > 4096
                    or any(ord(c) < 32 or ord(c) == 127 for c in entry["link"])):
                raise ValueError("signed capacity file record is malformed")
            path = pathname(entry["path"])
            if path in seen_paths:
                raise ValueError("signed capacity inventory duplicates a package path")
            seen_paths.add(path)
            files.append(entry)
            payload_bytes += entry["bytes"]
            if not entry["flags"] & 64:  # Ghost entries have no packaged payload.
                kind = stat.S_IFMT(entry["mode"])
                if kind not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK) or (path == "/" and kind != stat.S_IFDIR):
                    raise ValueError("capacity refuses special destination objects")
                layout = (kind, entry["link"] if kind == stat.S_IFLNK else "")
                if path in types and types[path] != layout:
                    raise ValueError("batch changes a shared destination kind or link")
                types[path] = layout
    if (len(files) != receipt.get("files") or len(files) > 131072
            or header_bytes > 64 * 1024 * 1024 or payload_bytes > 64 * 1024 ** 3):
        raise ValueError("capacity inventory exceeds its bounds")

    mount_data = Path("/proc/self/mountinfo").read_bytes()
    if not 0 < len(mount_data) <= 4 * 1024 * 1024:
        raise ValueError("mount inventory exceeds its bounds")
    mounts = {}
    for line in mount_data.decode("utf-8").splitlines():
        left, right = line.split(" - ", 1)
        fields, details = left.split(), right.split()
        number = int(fields[0])
        if number in mounts or len(fields) < 6 or len(details) != 3:
            raise ValueError("mount inventory is malformed")
        mounts[number] = {"device": tuple(map(int, fields[2].split(":"))), "fs": details[0],
                          "source": details[1], "options": set(fields[5].split(",") + details[2].split(","))}
    if not 0 < len(mounts) <= 4096:
        raise ValueError("mount count is unsupported")

    def forbidden(path):
        return any(path == prefix or path.startswith(prefix + "/") for prefix in
                   ("/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/run", "/var/lock"))

    def resolve(path):
        # Traverse only directories. Never open a FIFO/device/socket as input.
        pending = list(PurePosixPath(path).parts[1:])
        if len(pending) > 64:
            raise ValueError("destination ancestry exceeds its depth bound")
        fd, parts, trace, missing, links = dir_open("/"), [], [], [], 0
        try:
            observed = os.fstat(fd)
            trusted(observed)
            trace.append(("/", identity(observed), mount_id(fd)))
            while pending:
                name = pending.pop(0)
                if name in ("", "."):
                    continue
                if name == "..":
                    raise ValueError("destination symlink contains unsupported parent traversal")
                current = "/" + "/".join(parts + [name])
                if forbidden(current):
                    raise ValueError("capacity destination is a runtime or special filesystem path")
                planned = types.get(current)
                if missing:
                    entry = None
                else:
                    try:
                        entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        entry = None
                if entry is None:
                    if planned and planned[0] != stat.S_IFDIR:
                        raise ValueError("batch creates a non-directory destination ancestor")
                    parts.append(name)
                    missing.append(current)
                    continue
                if stat.S_ISLNK(entry.st_mode):
                    if entry.st_uid not in (0, os.geteuid()):
                        raise ValueError("destination symlink owner is untrusted")
                    target = os.readlink(name, dir_fd=fd)
                    if planned and planned != (stat.S_IFLNK, target):
                        raise ValueError("batch changes a destination symlink ancestor")
                    links += 1
                    if links > 40 or not target or len(target.encode("utf-8")) > 4096:
                        raise ValueError("destination symlink traversal exceeds its bound")
                    trace.append((current, identity(entry), target))
                    if target.startswith("/"):
                        os.close(fd)
                        fd, parts = dir_open("/"), []
                    pending = list(PurePosixPath(target).parts[1:] if target.startswith("/")
                                   else PurePosixPath(target).parts) + pending
                    if len(parts) + len(pending) > 64:
                        raise ValueError("resolved destination ancestry exceeds its bound")
                    continue
                if not stat.S_ISDIR(entry.st_mode) or (planned and planned[0] != stat.S_IFDIR):
                    raise ValueError("destination ancestor is not a retained directory")
                trusted(entry)
                next_fd = dir_open(name, fd)
                if identity(os.fstat(next_fd)) != identity(entry):
                    os.close(next_fd)
                    raise ValueError("destination changed during descriptor traversal")
                trace.append((current, identity(entry), mount_id(next_fd)))
                os.close(fd)
                fd = next_fd
                parts.append(name)
            return fd, (tuple(trace), tuple(missing), "/" + "/".join(parts))
        except BaseException:
            os.close(fd)
            raise

    volumes, observations, missing_dirs = {}, {}, set()
    def availability(fd):
        value = os.fstatvfs(fd)
        if (value.f_flag & os.ST_RDONLY or any(type(getattr(value, key)) is not int for key in
                ("f_frsize", "f_bsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_favail"))
                or not 512 <= value.f_frsize <= 1024 * 1024 or value.f_frsize & (value.f_frsize - 1)
                or not 512 <= value.f_bsize <= 1024 * 1024 or value.f_bsize & (value.f_bsize - 1)
                or not 0 <= value.f_bavail <= value.f_bfree <= value.f_blocks or value.f_blocks <= 0
                or not 0 <= value.f_favail <= value.f_ffree <= value.f_files or value.f_files <= 0):
            raise ValueError("filesystem does not advertise bounded writable block/inode availability")
        return {"allocation": max(value.f_frsize, value.f_bsize), "unit": value.f_frsize,
                "blocks": value.f_blocks, "inodes": value.f_files,
                "available_bytes": value.f_bavail * value.f_frsize, "available_inodes": value.f_favail}

    def volume(fd):
        observed, number = os.fstat(fd), mount_id(fd)
        mount = mounts.get(number)
        if (not mount or mount["device"] != (os.major(observed.st_dev), os.minor(observed.st_dev))
                or mount["fs"] not in ("ext4", "xfs") or not mount["source"].startswith("/dev/")
                or "rw" not in mount["options"] or "ro" in mount["options"]
                or any("quota" in option and option != "noquota" or option.split("=", 1)[0] in
                       {"uquota", "gquota", "pquota", "uqnoenforce", "gqnoenforce", "pqnoenforce", "qnoenforce", "jqfmt"}
                       for option in mount["options"])):
            raise ValueError("capacity supports only local ext4/xfs without advertised quota options")
        current = availability(fd)
        device = observed.st_dev
        if device not in volumes:
            if len(volumes) >= 64:
                raise ValueError("capacity filesystem count exceeds its bound")
            volumes[device] = {"device": device, "filesystem": mount["fs"], "mount_ids": set(),
                               "required_bytes": 0, "required_inodes": 0, "initial": current, "fds": []}
        result = volumes[device]
        initial = result["initial"]
        if (result["filesystem"] != mount["fs"] or any(initial[k] != current[k] for k in
                ("allocation", "unit", "blocks", "inodes"))):
            raise ValueError("filesystem aliases advertise inconsistent capacity geometry")
        initial["available_bytes"] = min(initial["available_bytes"], current["available_bytes"])
        initial["available_inodes"] = min(initial["available_inodes"], current["available_inodes"])
        if number not in result["mount_ids"]:
            result["mount_ids"].add(number)
            duplicate = os.dup(fd)
            held.append(duplicate)
            result["fds"].append(duplicate)
        return result

    def charge(path, size, is_directory=False):
        if forbidden(path):
            raise ValueError("capacity destination is a runtime or special filesystem path")
        parent = path if is_directory else str(PurePosixPath(path).parent)
        fd, signature = resolve(parent)
        try:
            if parent in observations and observations[parent] != signature:
                raise ValueError("destination layout changed between inventory entries")
            observations[parent] = signature
            if len(observations) > 32768:
                raise ValueError("destination parent count exceeds its bound")
            result = volume(fd)
            if not is_directory and not signature[1]:
                try:
                    entry = os.stat(PurePosixPath(path).name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    entry = None
                if entry is not None:
                    # Ordinary symlink mode0777 is not an access permission.
                    # Check its owner; protected parent traversal and the kind,
                    # no-follow descriptor identity/mount checks still apply.
                    if stat.S_ISLNK(entry.st_mode):
                        if entry.st_uid not in (0, os.geteuid()):
                            raise ValueError("capacity destination symlink has an untrusted owner")
                    else:
                        trusted(entry)
                    if stat.S_IFMT(entry.st_mode) != types[path][0]:
                        raise ValueError("existing destination kind differs from the signed payload")
                    descriptor = os.open(PurePosixPath(path).name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        if identity(os.fstat(descriptor)) != identity(entry) or mount_id(descriptor) != mount_id(fd):
                            raise ValueError("destination is changed or a file mount")
                    finally:
                        os.close(descriptor)
            allocation = result["initial"]["allocation"]
            # No erasure/replacement, hardlink, sparse or doc-skip credit.
            # Two full incoming copies plus two metadata blocks per entry.
            result["required_bytes"] += 2 * ((size + allocation - 1) // allocation + 2) * allocation
            result["required_inodes"] += 2
            for missing in signature[1]:
                key = (result["device"], missing)
                if key not in missing_dirs:
                    missing_dirs.add(key)
                    result["required_bytes"] += 4 * allocation
                    result["required_inodes"] += 2
            if len(missing_dirs) > 65536:
                raise ValueError("new destination directory count exceeds its bound")
        finally:
            os.close(fd)

    skipped_ghosts = 0
    for entry in files:
        if entry["flags"] & 64:
            skipped_ghosts += 1
            continue
        charge(entry["path"], max(entry["bytes"], len(entry["link"].encode("utf-8"))),
               stat.S_ISDIR(entry["mode"]))

    def database_scan():
        fd, signature = resolve(database)
        rows, total = [], 0
        result = volume(fd)
        def walk(directory, prefix, depth):
            nonlocal total
            if depth > 8:
                raise ValueError("database directory depth exceeds its bound")
            for name in sorted(os.listdir(directory)):
                observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                trusted(observed)
                if observed.st_dev != result["device"]:
                    raise ValueError("database spans unsupported filesystem boundaries")
                path = prefix + "/" + name
                rows.append((path, identity(observed), observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns))
                if len(rows) > 8192:
                    raise ValueError("database file count exceeds its bound")
                if stat.S_ISDIR(observed.st_mode):
                    child = dir_open(name, directory)
                    try:
                        if identity(os.fstat(child)) != identity(observed) or mount_id(child) != mount_id(directory):
                            raise ValueError("database directory changed or crosses a mount")
                        walk(child, path, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1:
                    total += max(observed.st_size, observed.st_blocks * 512)
                    if total > 2 * 1024 ** 3:
                        raise ValueError("database allocation exceeds its inspection bound")
                else:
                    raise ValueError("database has an unsupported non-regular or linked object")
        try:
            if signature[1]:
                raise ValueError("installed database directory is missing")
            walk(fd, "", 0)
            if not rows:
                raise ValueError("installed database directory is empty")
            return result, (signature, rows, total)
        finally:
            os.close(fd)
    db_volume, db_before = database_scan()
    db_volume["required_bytes"] += 2 * db_before[2] + 4 * header_bytes + 64 * 1024 * 1024
    db_volume["required_inodes"] += 2 * len(db_before[1]) + 4 * len(expected) + 64

    for parent, before in observations.items():
        fd, after = resolve(parent)
        try:
            if after != before:
                raise ValueError("destination ancestry changed during capacity observation")
            volume(fd)
        finally:
            os.close(fd)
    _, db_after = database_scan()
    if db_after != db_before or Path("/proc/self/mountinfo").read_bytes() != mount_data:
        raise ValueError("database or mount layout changed during capacity observation")
    results = []
    for result in volumes.values():
        initial = result["initial"]
        available_bytes, available_inodes = initial["available_bytes"], initial["available_inodes"]
        for fd in result["fds"]:
            current = availability(fd)
            if any(current[key] != initial[key] for key in ("allocation", "unit", "blocks", "inodes")):
                raise ValueError("filesystem geometry changed during capacity observation")
            available_bytes = min(available_bytes, current["available_bytes"])
            available_inodes = min(available_inodes, current["available_inodes"])
        reserve_bytes = max(64 * 1024 * 1024, (initial["blocks"] * initial["unit"] + 19) // 20)
        reserve_inodes = max(256, (initial["inodes"] + 19) // 20)
        if (available_bytes < result["required_bytes"] + reserve_bytes
                or available_inodes < result["required_inodes"] + reserve_inodes):
            raise ValueError("advertised free blocks/inodes do not meet payload budget plus headroom")
        results.append({key: result[key] for key in ("device", "filesystem", "required_bytes", "required_inodes")}
                       | {"mount_ids": sorted(result["mount_ids"]), "available_bytes": available_bytes,
                          "available_inodes": available_inodes, "headroom_bytes": reserve_bytes,
                          "headroom_inodes": reserve_inodes})
    proof["payload_capacity_checked"] = True
    proof["capacity_observation"] = {"filesystems": sorted(results, key=lambda item: item["device"]),
        "inventory_sha256": receipt["sha256"], "skipped_ghost_entries": skipped_ghosts,
        "policy": "two gross incoming copies plus per-entry metadata; no removal/hardlink credit; database reserve; five-percent or fixed headroom",
        "space_reserved": False, "scripts_capacity_checked": False, "rollback_capacity_checked": False,
        "quota_enforcement_queried": False, "atomic_filesystem_snapshot": False,
        "observer_limits": {"address_space_bytes": 768 * 1024 * 1024,
                            "cpu_soft_seconds": 240, "descriptor_soft_limit": descriptor_limit}}
    print(json.dumps(proof, sort_keys=True))
except (ValueError, KeyError, TypeError, OSError, UnicodeError, IndexError, MemoryError) as error:
    print("azurelinux3s4: update payload capacity deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
finally:
    for fd in held:
        os.close(fd)
PY
}

s4_update_interpreters_program() {
    # File observations only; no script/interpreter/Lua execution or selection.
    cat <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys


TRUSTED_UID = 0
ORDINARY = (("prein", 1023, 1085), ("postin", 1024, 1086),
            ("preun", 1025, 1087), ("postun", 1026, 1088),
            ("pretrans", 1151, 1153), ("posttrans", 1152, 1154),
            ("verify", 1079, 1091))
TRIGGERS = (("trigger", 1065, 1092), ("filetrigger", 5066, 5067),
            ("transfiletrigger", 5076, 5077))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def trusted(value):
    if value.st_uid != TRUSTED_UID or value.st_mode & 0o022:
        raise ValueError("interpreter file or directory has untrusted ownership/permissions")


def pathname(value):
    if (not isinstance(value, str) or not value.startswith("/") or value == "/"
            or "//" in value or value.endswith("/") or len(value.encode("utf-8")) > 4096
            or any(part in (".", "..") for part in value.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("interpreter requires a canonical absolute path")
    return value


def mount_id(fd):
    entries = re.findall(r"^mnt_id:\s*([0-9]+)$", Path(f"/proc/self/fdinfo/{fd}").read_text(), re.M)
    if len(entries) != 1:
        raise ValueError("interpreter descriptor mount identity is unavailable")
    return int(entries[0])


def root_open():
    return os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def resolve(path):
    # Walk protected ancestors, including ordinary owned aliases, using checked
    # no-follow descriptors. No interpreter or script is executed.
    pending, parts, trace, links, steps = pathname(path).split("/")[1:], [], [], 0, 0
    fd = root_open()
    try:
        trusted(os.fstat(fd))
        trace.append(("/", identity(os.fstat(fd)), mount_id(fd)))
        while pending:
            steps += 1
            if steps > 1024 or len(parts) + len(pending) > 64:
                raise ValueError("interpreter traversal exceeds its finite bound")
            name = pending.pop(0)
            if name in ("", "."):
                continue
            if name == "..":
                # Re-walk the observed physical parent; never lexically collapse
                # an untraversed link/.. sequence into a different target.
                pending = parts[:-1] + pending
                parts = []
                os.close(fd)
                fd = root_open()
                trusted(os.fstat(fd))
                trace.append(("/", identity(os.fstat(fd)), mount_id(fd)))
                continue
            current = "/" + "/".join(parts + [name])
            if any(current == p or current.startswith(p + "/") for p in
                   ("/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/run", "/var/lock")):
                raise ValueError("interpreter resolves through a special/runtime path")
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            opened = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                observed = os.fstat(opened)
                if identity(observed) != identity(before):
                    raise ValueError("interpreter path changed before descriptor acquisition")
                number = mount_id(opened)
                if stat.S_ISLNK(observed.st_mode):
                    # Ordinary symlink 0777 is not an access permission mask.
                    if observed.st_uid != TRUSTED_UID:
                        raise ValueError("interpreter symlink has an untrusted owner")
                    target = os.readlink("", dir_fd=opened)
                    links += 1
                    if (links > 40 or not target or len(target.encode("utf-8")) > 4096
                            or any(ord(c) < 32 or ord(c) == 127 for c in target)):
                        raise ValueError("interpreter symlink traversal is unsupported")
                    trace.append((current, identity(observed), number, target))
                    if target.startswith("/"):
                        parts = []
                        os.close(fd)
                        fd = root_open()
                        trusted(os.fstat(fd))
                        trace.append(("/", identity(os.fstat(fd)), mount_id(fd)))
                    pending = target.split("/") + pending
                    continue
                trusted(observed)
                trace.append((current, identity(observed), number))
                if pending:
                    if not stat.S_ISDIR(observed.st_mode):
                        raise ValueError("interpreter ancestor is not a directory")
                    next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                      os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                    if identity(os.fstat(next_fd)) != identity(observed):
                        os.close(next_fd)
                        raise ValueError("interpreter directory changed during traversal")
                    os.close(fd)
                    fd = next_fd
                    parts.append(name)
                    continue
                if (not stat.S_ISREG(observed.st_mode) or not observed.st_mode & 0o111
                        or not 0 < observed.st_size <= 64 * 1024 * 1024):
                    raise ValueError("interpreter is not a bounded executable regular file")
                if os.fstatvfs(opened).f_flag & os.ST_NOEXEC:
                    raise ValueError("interpreter file mount is noexec")
                result = (current, identity(observed), tuple(trace))
                # Duplicate the checked regular inode, not the original path.
                # Reading through this kernel fd link cannot reopen a raced
                # FIFO/device/symlink in the operator's filesystem namespace.
                reader = os.open(f"/proc/self/fd/{opened}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                if identity(os.fstat(reader)) != identity(observed):
                    os.close(reader)
                    raise ValueError("interpreter read descriptor differs from its observed inode")
                return reader, result
            finally:
                os.close(opened)
        raise ValueError("interpreter path did not resolve to a regular file")
    finally:
        os.close(fd)


def declarations(owner):
    tags = owner["tags"]
    if not isinstance(tags, list) or len(tags) > 44:
        raise ValueError("interpreter metadata exceeds its catalog bound")
    by_tag = {}
    for entry in tags:
        if (type(entry["tag"]) is not int or entry["tag"] in by_tag
                or type(entry["count"]) is not int or not 0 < entry["count"] <= 4096
                or not isinstance(entry["values"], list) or len(entry["values"]) != entry["count"]):
            raise ValueError("interpreter metadata is malformed or duplicated")
        by_tag[entry["tag"]] = entry
    for family, body, program in ORDINARY:
        if body in by_tag or program in by_tag:
            values = by_tag[program]["values"] if program in by_tag else ["/bin/sh"]
            yield family, 0, values, program not in by_tag
    for family, body, program in TRIGGERS:
        if body not in by_tag and program not in by_tag:
            continue
        if (body not in by_tag or program not in by_tag
                or by_tag[body]["count"] != by_tag[program]["count"]):
            raise ValueError("trigger body/program arrays require matching declared entries")
        for index, value in enumerate(by_tag[program]["values"]):
            yield family, index, [value], False


def observe(proof):
    audit = proof["effects"]
    if (proof.get("schema") != 1 or proof.get("test_passed") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", proof["manifest_sha256"])
            or any(proof.get(name) is not False for name in
                   ("installation_authorized", "scripts_executed", "installs_performed",
                    "storage_capacity_checked", "freshness_proven"))
            or audit.get("schema") != 1 or audit.get("script_metadata_observed") is not True
            or audit.get("removals_bound_to_installed_instances") is not True
            or audit["installed_headers_observed"] != proof["baseline"]["headers"]
            or any(audit.get(name) is not False for name in
                   ("installed_headers_authenticated", "trigger_selection_complete",
                    "script_execution_plan_complete", "script_policy_satisfied",
                    "removal_policy_satisfied", "rollback_policy_satisfied"))):
        raise ValueError("interpreter input lacks the qualified fresh same-byte effects TEST")
    incoming, installed = audit["incoming"], audit["installed_script_owners"]
    if (not isinstance(incoming, list) or len(incoming) > 128
            or not isinstance(installed, list) or len(installed) > 32768
            or len(incoming) != len(proof["additions"])):
        raise ValueError("interpreter owner inventory is unsupported")
    expected = {(p["file"], p["sha256"], p["bytes"], p["nevra"]) for p in proof["additions"]}
    if len(expected) != len(incoming) or expected != {
            (p["file"], p["sha256"], p["bytes"], p["nevra"]) for p in incoming}:
        raise ValueError("interpreter incoming identities differ from the admitted TEST inputs")
    refs, files, receipts, seen_instances, total = [], {}, {}, set(), 0
    for source, owners in (("incoming", incoming), ("installed", installed)):
        for owner in owners:
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", owner["name"])
                    or not isinstance(owner["nevra"], str) or not 0 < len(owner["nevra"]) <= 1024
                    or not re.fullmatch(r"[0-9a-f]{64}", owner["header_sha256"])):
                raise ValueError("interpreter owner identity is malformed")
            binding = {name: owner[name] for name in ("name", "nevra", "header_sha256")}
            if source == "installed":
                instance = owner["instance"]
                if type(instance) is not int or instance <= 0 or instance in seen_instances:
                    raise ValueError("interpreter installed instance is missing or duplicated")
                seen_instances.add(instance)
                binding["instance"] = instance
            else:
                binding.update({name: owner[name] for name in ("file", "sha256", "bytes")})
            for family, index, argv, default in declarations(owner):
                if (not argv or any(not isinstance(arg, str) or not arg or len(arg.encode("utf-8")) > 4096
                                    or any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in argv)):
                    raise ValueError("declared interpreter argv is unsupported")
                command = argv[0]
                kind = "embedded-lua" if command == "<lua>" else "external-file"
                if kind == "external-file":
                    pathname(command)
                    if command not in files:
                        if len(files) >= 64:
                            raise ValueError("unique interpreter file count exceeds its bound")
                        fd, receipt = resolve(command)
                        with os.fdopen(fd, "rb") as stream:
                            before = os.fstat(stream.fileno())
                            digest, size = hashlib.sha256(), 0
                            while block := stream.read(1024 * 1024):
                                digest.update(block)
                                size += len(block)
                                if size > 64 * 1024 * 1024:
                                    raise ValueError("interpreter grew beyond its read bound")
                            if identity(os.fstat(stream.fileno())) != identity(before) or size != before.st_size:
                                raise ValueError("interpreter file changed during hashing")
                        total += size
                        if total > 256 * 1024 * 1024:
                            raise ValueError("interpreter bytes exceed the aggregate bound")
                        receipts[command] = receipt
                        files[command] = {"path": command, "resolved_path": receipt[0], "bytes": size,
                                          "sha256": digest.hexdigest(), "device": before.st_dev,
                                          "inode": before.st_ino, "mode": before.st_mode, "uid": before.st_uid,
                                          "mount_id": receipt[2][-1][2], "mount_noexec": False}
                refs.append({"source": source, "owner": binding, "family": family, "index": index,
                             "argv": argv, "default_program": default, "kind": kind})
                if len(refs) > 65536:
                    raise ValueError("declared interpreter references exceed their bound")
    for command, receipt in receipts.items():
        fd, after = resolve(command)
        os.close(fd)
        if after != receipt:
            raise ValueError("interpreter path or file changed during the observation")
    proof["interpreters"] = {
        "schema": 1, "references": refs, "files": [files[p] for p in sorted(files)],
        "external_files_observed": True, "embedded_lua_declarations": sum(r["kind"] == "embedded-lua" for r in refs),
        "scope": "all-declared-incoming-and-installed; selection is unproved",
        "runtime_files_authenticated": False, "embedded_engines_tested": False,
        "interpreter_loadability_checked": False, "interpreter_dependencies_checked": False,
        "execution_tested": False, "execution_policy_satisfied": False,
        "trigger_selection_complete": False, "installation_authorized": False,
    }
    return proof


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (240, 245))
        path = Path(sys.argv[1]) / "result.json"
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 32 * 1024 * 1024):
            raise ValueError("interpreter proof is not a bounded private regular file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise ValueError("interpreter proof changed before opening")
            data = stream.read(32 * 1024 * 1024 + 1)
            if identity(os.fstat(stream.fileno())) != identity(before) or len(data) != before.st_size:
                raise ValueError("interpreter proof changed during reading")
        encoded = json.dumps(observe(json.loads(data)), sort_keys=True)
        if len(encoded.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("interpreter observations exceed their output bound")
        print(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, OverflowError, IndexError) as error:
        print("Update interpreter observation deferred: " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
PY
}

s4_update_removals_program() {
    # A conservative replacement prerequisite, not full removal/installation policy.
    cat <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys


KERNELS = frozenset(("kernel", "kernel-mshv", "kernel-uvm", "kernel-uki", "kernel-64k", "kernel-hwe"))
LIMIT = 32 * 1024 * 1024


def number(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("removal evidence integer is missing or excessive")
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("removal evidence digest is invalid")
    return value


def package(value):
    name, nevra = value["name"], value["nevra"]
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", name)
            or not isinstance(nevra, str) or len(nevra) > 1024 or not nevra.startswith(name + "-")):
        raise ValueError("package name and native identity are inconsistent")
    # Parse only the bounded canonical binary NEVRA subset emitted by RPM.
    # No RPM version comparison, dependency or renamed-provider equivalence is
    # inferred from these strings. Unsupported identities remain pending.
    match = re.fullmatch(r"(?:[0-9]+:)?[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+\.(x86_64|aarch64|noarch)",
                         nevra[len(name) + 1:])
    if not match:
        raise ValueError("package identity is outside the supported binary NEVRA subset")
    number(value["header_bytes"], 8, 8 * 1024 * 1024)
    digest(value["header_sha256"])
    return name, match[1]


def artifact(value):
    path = value["file"]
    if not isinstance(path, str) or not re.fullmatch(r"packages/(?:0|[1-9][0-9]{0,2})\.rpm", path):
        raise ValueError("incoming artifact does not identify a private snapshot")
    number(int(path[9:-4]), 0, 127)
    number(value["bytes"], 1, 512 * 1024 * 1024)
    digest(value["sha256"])
    if not isinstance(value["nevra"], str) or len(value["nevra"]) > 1024:
        raise ValueError("incoming native identity is invalid")
    return path, value["sha256"], value["bytes"], value["nevra"]


def observe(proof):
    if not isinstance(proof, dict):
        raise ValueError("removal evidence is not an object")
    if type(proof.get("schema")) is not int or proof["schema"] != 1 or proof.get("test_passed") is not True:
        raise ValueError("removal evidence lacks the current native TEST result")
    for flag in ("installs_performed", "scripts_executed", "installation_authorized",
                 "storage_capacity_checked", "freshness_proven"):
        if proof.get(flag) is not False:
            raise ValueError("removal evidence exceeds its diagnostic authority")
    digest(proof["manifest_sha256"])
    baseline = proof["baseline"]
    if not isinstance(baseline, dict):
        raise ValueError("installed observation is missing")
    headers = number(baseline["headers"], 1, 32768)
    digest(baseline["sha256"])
    audit = proof["effects"]
    if (not isinstance(audit, dict) or type(audit.get("schema")) is not int or audit["schema"] != 1
            or audit.get("script_metadata_observed") is not True
            or audit.get("removals_bound_to_installed_instances") is not True
            or type(audit.get("installed_headers_observed")) is not int
            or audit["installed_headers_observed"] != headers):
        raise ValueError("removal evidence lacks bound installed-instance observations")
    for flag in ("installed_headers_authenticated", "trigger_selection_complete", "script_execution_plan_complete",
                 "script_policy_satisfied", "removal_policy_satisfied", "rollback_policy_satisfied"):
        if audit.get(flag) is not False:
            raise ValueError("removal evidence claims an unestablished policy")
    incoming, additions, removals, identities = audit["incoming"], proof["additions"], audit["removals"], proof["removals"]
    if (any(not isinstance(value, list) for value in (incoming, additions, removals, identities))
            or len(incoming) != len(additions) or len(incoming) > 128
            or len(removals) != len(identities) or len(removals) > headers):
        raise ValueError("removal evidence inventories are inconsistent or excessive")
    if proof.get("rpm_test_performed") is not bool(additions) or (removals and not additions):
        raise ValueError("a removal must come from a nonempty current package TEST")
    if any(not isinstance(value, dict) for value in incoming + additions + removals):
        raise ValueError("removal evidence record is not an object")
    if sorted(map(artifact, incoming)) != sorted(map(artifact, additions)):
        raise ValueError("incoming observations differ from the SAME tested snapshots")
    if [value["nevra"] for value in removals] != identities:
        raise ValueError("removal inventory differs from the native TEST elements")
    snapshots, replacements = {}, {}
    for value in incoming:
        binding, key = artifact(value), package(value)
        if binding[0] in snapshots or key in replacements:
            raise ValueError("incoming replacement is duplicated or ambiguous")
        snapshots[binding[0]] = value
        replacements[key] = value
    for value in additions:
        if type(value.get("install_only")) is not bool or type(value.get("pretrans_present")) is not bool:
            raise ValueError("incoming native element flags are missing")
        source = snapshots[value["file"]]
        if value["install_only"] != (source["name"] in KERNELS):
            raise ValueError("incoming kernel retention mode is inconsistent")
    instances, used, matches = set(), set(), []
    for removed in removals:
        key = package(removed)
        instance = number(removed["instance"], 1, 2 ** 32 - 1)
        if instance in instances or key in used:
            raise ValueError("removed installed instance or replacement is repeated")
        instances.add(instance)
        if key[0] in KERNELS:
            raise ValueError("installed kernel removal is outside the update safeguard")
        replacement = replacements.get(key)
        if replacement is None or removed.get("classification") != "same-name-replacement":
            raise ValueError("installed removal lacks a unique SAME-name-and-architecture replacement")
        if removed["nevra"] == replacement["nevra"]:
            raise ValueError("same-identity erase/reinstall is outside the update safeguard")
        used.add(key)
        matches.append({"instance": instance, "name": key[0], "architecture": key[1],
                        "removed_nevra": removed["nevra"], "removed_header_sha256": removed["header_sha256"],
                        "replacement_nevra": replacement["nevra"], "file": replacement["file"],
                        "sha256": replacement["sha256"], "bytes": replacement["bytes"],
                        "replacement_header_sha256": replacement["header_sha256"]})
    proof["removal_guard"] = {"schema": 1, "matches": matches,
        "same_name_architecture_replacements_only": True, "kernel_removals_refused": True,
        "scope": "current TEST elements; one removed instance per unique same-name/architecture incoming snapshot",
        "versions_compared_by_guard": False, "package_continuity_proven": False,
        "critical_package_closure_complete": False, "removal_policy_satisfied": False,
        "rollback_policy_satisfied": False, "installation_authorized": False}
    return proof


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("removal evidence has a duplicate JSON field")
        result[key] = value
    return result


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        path = Path(sys.argv[1]) / "result.json"
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= LIMIT):
            raise ValueError("removal proof is not a bounded private regular file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise ValueError("removal proof changed before opening")
            data = stream.read(LIMIT + 1)
            if identity(os.fstat(stream.fileno())) != identity(before) or len(data) != before.st_size:
                raise ValueError("removal proof changed while reading")
        proof = observe(json.loads(data, object_pairs_hook=unique_object))
        proof["removal_guard"]["input_sha256"] = hashlib.sha256(data).hexdigest()
        encoded = json.dumps(proof, sort_keys=True)
        if len(encoded.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("removal observations exceed their output bound")
        print(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, OverflowError, IndexError, StopIteration) as error:
        print("Update removal safeguard deferred: " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
PY
}

s4_check_updates() (
    command -v systemd-run >/dev/null && command -v rpmkeys >/dev/null || return 75
    local directory database evidence
    if [[ -n $S4_INTERPRETERS_MODE ]]; then
        [[ $S4_INTERPRETERS_MODE == yes && $S4_EFFECTS_MODE == yes && -z $S4_CAPACITY_MODE && -z $S4_REMOVALS_MODE ]] || return 75
    fi
    if [[ -n $S4_REMOVALS_MODE ]]; then
        [[ $S4_REMOVALS_MODE == yes && $S4_EFFECTS_MODE == yes && -z $S4_CAPACITY_MODE && -z $S4_INTERPRETERS_MODE ]] || return 75
    fi
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
    if [[ $S4_EFFECTS_MODE == yes ]]; then
        [[ -z $S4_CAPACITY_MODE ]] || return 75
        s4_rpm_effects_program >"$directory/test.py" || return 75
    else
        : >"$directory/test.py"
    fi
    s4_rpm_test_program >>"$directory/test.py" || return 75
    if timeout --signal=TERM --kill-after=30s 15m python3 -I - "$directory" "$database" "$S4_ARCH" "$S4_CAPACITY_MODE" "$S4_EFFECTS_MODE" <<'PY'
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
try:
    root = Path(sys.argv[1])
    capacity = sys.argv[4] == "yes"
    effects = sys.argv[5] == "yes"
    if sys.argv[4] not in ("", "yes") or sys.argv[5] not in ("", "yes") or (capacity and effects):
        raise ValueError("unsupported internal diagnostic mode")
    output_limit = 32 * 1024 * 1024 if capacity or effects else 1048576
    evidence_limit = 32 * 1024 * 1024 if effects else 1048576
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
        "--property=LimitFSIZE=" + str(output_limit), "--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket",
        "--property=UnsetEnvironment=RPM_CONFIGDIR RPM_POPTEXEC_PATH LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH",
        "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
        "--setenv=HOME=" + str(root / "home"), "--", "python3", "-I", str(root / "test.py"), str(root),
        *sys.argv[2:4], *(["capacity"] if capacity else ["effects"] if effects else [])]
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
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
    if code or not 0 < len(data) <= evidence_limit:
        print(data[:65536].decode("utf-8", "replace"), file=sys.stderr)
        raise ValueError("native RPM test did not provide bounded successful evidence")
    proof = json.loads(data)
    if (proof.get("schema") != 1 or proof.get("test_passed") is not True
            or any(proof.get(name) is not False for name in ("installs_performed", "scripts_executed", "installation_authorized", "storage_capacity_checked", "freshness_proven"))):
        raise ValueError("native test evidence is incomplete")
    if effects:
        observed = proof.get("effects", {})
        if (observed.get("schema") != 1 or observed.get("script_metadata_observed") is not True
                or observed.get("removals_bound_to_installed_instances") is not True
                or observed.get("installed_headers_observed") != proof["baseline"]["headers"]
                or len(observed["incoming"]) != len(proof["additions"])
                or [value["nevra"] for value in observed["removals"]] != proof["removals"]
                or any(observed.get(name) is not False for name in ("installed_headers_authenticated",
                    "trigger_selection_complete", "script_execution_plan_complete", "script_policy_satisfied",
                    "removal_policy_satisfied", "rollback_policy_satisfied"))):
            raise ValueError("native effects evidence is incomplete")
    (root / "result.json").write_text(json.dumps(proof, sort_keys=True) + "\n")
except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: update compatibility deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
    then
        if [[ $S4_REMOVALS_MODE == yes ]]; then
            s4_update_removals_program >"$directory/removals.py" || return 75
            evidence=$(timeout --kill-after=5s 90s python3 -I "$directory/removals.py" "$directory") || return 75
        elif [[ $S4_INTERPRETERS_MODE == yes ]]; then
            s4_update_interpreters_program >"$directory/interpreters.py" || return 75
            evidence=$(timeout --kill-after=5s 5m python3 -I "$directory/interpreters.py" "$directory") || return 75
        elif [[ $S4_CAPACITY_MODE == yes ]]; then
            s4_update_capacity_program >"$directory/capacity.py" || return 75
            evidence=$(timeout --kill-after=5s 5m python3 -I "$directory/capacity.py" "$directory" "$database") || return 75
        else
            evidence=$(cat -- "$directory/result.json") || return 75
        fi
    else
        return 75
    fi
    rm -rf -- "$directory" || return 75
    trap - EXIT
    if [[ $S4_REMOVALS_MODE == yes ]]; then
        s4_log 'Current TEST removals have unique same-name/architecture replacements; complete removal, rollback and installation policy remain unproved.'
    elif [[ $S4_INTERPRETERS_MODE == yes ]]; then
        s4_log 'Declared interpreter files observed; embedded Lua, loadability, dependencies and execution policy remain unproved.'
    elif [[ $S4_EFFECTS_MODE == yes ]]; then
        s4_log 'Declared script metadata and installed removal identities observed; execution policy remains unfinished.'
    elif [[ $S4_CAPACITY_MODE == yes ]]; then
        s4_log 'Advertised payload capacity meets the signed-batch budget; scripts/rollback/installation remain unfinished.'
    else
        s4_log 'Retained signed RPM batch passed its read-only transaction test; installation is unfinished.'
    fi
    printf '%s\n' "$evidence"
)

s4_check_update_capacity() (
    local S4_CAPACITY_MODE=yes
    s4_check_updates
)

s4_check_update_effects() (
    local S4_EFFECTS_MODE=yes
    s4_check_updates
)

s4_check_update_interpreters() (
    local S4_EFFECTS_MODE=yes S4_INTERPRETERS_MODE=yes
    s4_check_updates
)

s4_check_update_removals() (
    local S4_EFFECTS_MODE=yes S4_REMOVALS_MODE=yes
    s4_check_updates
)

s4_web_isolation_policy() {
    # Candidate bytes only. No package/account/unit/file installation or host
    # observation is performed, and this is not a setup-completion dependency.
    timeout --kill-after=5s 30s python3 -I - <<'PY'
RELAY_SOURCE = r'''
# Generated by Bootstrap/pack.py from Web/relay.py.in and declared Web helpers.
"""One accepted TCP connection to one Unix backend; no reconnect after sealing.

Candidate worker only. Credential/path observations do not authenticate the
runtime, authorize a caller or establish systemd/LSM confinement.
"""

import ctypes
import errno
import grp
import os
import platform
import pwd
import resource
import selectors
import socket
import stat
import struct
import sys
import time


"""Observe loaded native file identities; no signature or memory attestation."""

import hashlib
import os
import platform
import re
import signal
import stat
import struct
import time


RUNTIME_OWNER = 0
RUNTIME_MAP_BYTES = 1024 * 1024
RUNTIME_IMAGES = 128
RUNTIME_IMAGE_BYTES = 64 * 1024 * 1024
RUNTIME_TOTAL_BYTES = 256 * 1024 * 1024
RUNTIME_OBSERVE_SECONDS = 30
STARTUP_SECONDS = 60


class RuntimeStartup:
    """A sole worker's startup timer; forwarding has its separate deadline."""

    def __init__(self):
        self.armed = False
        self.handler = self.expired

    def expired(self, number, frame):
        raise TimeoutError("relay startup deadline reached")

    def __enter__(self):
        if (signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
                or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
                or signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, ())):
            raise ValueError("relay startup signal context refused")
        signal.signal(signal.SIGALRM, self.handler)
        try:
            signal.setitimer(signal.ITIMER_REAL, STARTUP_SECONDS)
        except BaseException:
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            raise
        self.armed = True
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        if signal.getsignal(signal.SIGALRM) is not self.handler or not 0 < remaining <= STARTUP_SECONDS or interval:
            self.disarm()
            raise RuntimeError("relay startup handler was not installed")
        return self

    def disarm(self):
        if not self.armed:
            return
        signal.setitimer(signal.ITIMER_REAL, 0)
        previous = signal.signal(signal.SIGALRM, signal.SIG_DFL)
        self.armed = False
        if (previous is not self.handler or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
                or signal.getsignal(signal.SIGALRM) != signal.SIG_DFL):
            raise RuntimeError("relay startup timer retirement was not observed")

    def __exit__(self, *exception):
        self.disarm()


def runtime_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or len(path.encode()) > 4096
            or not path.isascii() or any(ord(character) < 33 or ord(character) > 126 for character in path)
            or "\\" in path or path.endswith(" (deleted)")):
        raise ValueError("unsupported runtime image path")
    parts = path[1:].split("/")
    if len(parts) > 64 or any(part in ("", ".", "..") for part in parts):
        raise ValueError("noncanonical runtime image path")
    return parts


def runtime_maps(data=None):
    if data is None:
        descriptor = os.open("/proc/self/maps", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("runtime maps is not a regular proc observation")
            blocks, total = [], 0
            while block := os.read(descriptor, min(65536, RUNTIME_MAP_BYTES + 1 - total)):
                blocks.append(block)
                total += len(block)
                if total > RUNTIME_MAP_BYTES:
                    raise ValueError("runtime maps observation exceeds its bound")
            data = b"".join(blocks)
        finally:
            os.close(descriptor)
    if not isinstance(data, bytes) or not data or len(data) > RUNTIME_MAP_BYTES or not data.endswith(b"\n"):
        raise ValueError("runtime maps observation exceeds its bound or is truncated")
    records, images, paths, mapped_paths = [], {}, {}, {}
    lines = data.splitlines()
    if len(lines) > 4096:
        raise ValueError("runtime mapping inventory exceeds its bound")
    for line in lines:
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise ValueError("malformed runtime mapping")
        address, permissions, offset, device, inode = fields[:5]
        raw_path = fields[5] if len(fields) == 6 else b""
        if (not re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+", address)
                or not re.fullmatch(rb"[r-][w-][x-][ps]", permissions)
                or not re.fullmatch(rb"[0-9a-f]+", offset)
                or not re.fullmatch(rb"[0-9a-f]+:[0-9a-f]+", device)
                or not re.fullmatch(rb"[0-9]+", inode)):
            raise ValueError("malformed runtime mapping fields")
        start, end = (int(value, 16) for value in address.split(b"-"))
        major, minor = (int(value, 16) for value in device.split(b":"))
        identity = major, minor, int(inode)
        if not 0 <= start < end < 1 << 64 or any(value >= 1 << 64 for value in (*identity, int(offset, 16))):
            raise ValueError("runtime mapping integer bounds refused")
        if permissions[1:3] == b"wx":
            raise ValueError("writable executable runtime mapping refused")
        # Only executable image ranges are observed here. Read-only/writable
        # data mappings may split/merge during ordinary allocator activity.
        if permissions[2:3] != b"x":
            continue
        path = raw_path.decode("ascii")
        if "x" in permissions.decode() and identity[2] == 0:
            allowed = {"[vdso]", "[vsyscall]"} if platform.machine() == "x86_64" else {"[vdso]"}
            if path not in allowed:
                raise ValueError("anonymous executable runtime mapping refused")
            records.append((start, end, permissions.decode(), int(offset, 16), identity, path))
        if identity[2]:
            runtime_path(path)
            if path in paths and paths[path] != identity:
                raise ValueError("runtime path has ambiguous mapped identity")
            if identity in mapped_paths and mapped_paths[identity] != path:
                raise ValueError("runtime inode has ambiguous mapped paths")
            paths[path] = identity
            mapped_paths[identity] = path
            records.append((start, end, permissions.decode(), int(offset, 16), identity, path))
            images[identity] = path
            if len(paths) > RUNTIME_IMAGES:
                raise ValueError("runtime image inventory exceeds its bound")
        if len(records) > 4096:
            raise ValueError("runtime mapping inventory exceeds its bound")
    if not images:
        raise ValueError("runtime has no mapped executable image")
    return tuple(records), images


def runtime_root():
    return os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def runtime_mount(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb") as stream:
        data = stream.read(8193)
    values = [line.split(b":", 1)[1].strip() for line in data.splitlines() if line.startswith(b"mnt_id:")]
    if len(data) > 8192 or len(values) != 1 or not values[0].isdigit():
        raise ValueError("runtime descriptor mount identity unavailable")
    return int(values[0])


def runtime_identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def runtime_walk(path):
    descriptors, trace = [], []
    try:
        descriptors.append(runtime_root())
        parts = runtime_path(path)
        for index, name in enumerate((None, *parts)):
            if name is not None:
                descriptors.append(os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=descriptors[-1]))
            value = os.fstat(descriptors[-1])
            if value.st_uid != RUNTIME_OWNER or value.st_mode & 0o022:
                raise ValueError("unprotected runtime image ancestry or ownership")
            if index < len(parts):
                if not stat.S_ISDIR(value.st_mode):
                    raise ValueError("runtime image ancestry is not an alias-free directory")
            elif not stat.S_ISREG(value.st_mode):
                raise ValueError("runtime image leaf is not a regular file")
            trace.append((runtime_identity(value), runtime_mount(descriptors[-1])))
        return descriptors, trace
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def runtime_image(path, expected, deadline):
    descriptors, before = runtime_walk(path)
    opened = None
    try:
        leaf = os.fstat(descriptors[-1])
        if ((os.major(leaf.st_dev), os.minor(leaf.st_dev), leaf.st_ino) != expected
                or not 64 <= leaf.st_size <= RUNTIME_IMAGE_BYTES):
            raise ValueError("runtime image differs from mapped inode or size bound")
        opened = os.open(f"/proc/self/fd/{descriptors[-1]}", os.O_RDONLY | os.O_CLOEXEC)
        value = os.fstat(opened)
        if runtime_identity(value) != runtime_identity(leaf):
            raise ValueError("runtime hash descriptor differs from held inode")
        header = os.read(opened, 64)
        machine = {"x86_64": 62, "aarch64": 183}.get(platform.machine())
        if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
                or struct.unpack_from("<HHI", header, 16) not in ((2, machine, 1), (3, machine, 1))
                or struct.unpack_from("<H", header, 52)[0] != 64):
            raise ValueError("runtime image lacks the supported native ELF header")
        digest, total = hashlib.sha256(header), len(header)
        while block := os.read(opened, 1024 * 1024):
            total += len(block)
            if total > RUNTIME_IMAGE_BYTES or time.monotonic() >= deadline:
                raise ValueError("runtime image read exceeds its byte/time bound")
            digest.update(block)
        after = os.fstat(opened)
        content_identity = lambda item: (runtime_identity(item), item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if content_identity(value) != content_identity(after) or total != value.st_size:
            raise ValueError("runtime image changed while hashing")
        checked_descriptors, checked_trace = runtime_walk(path)
        try:
            if (checked_trace != before
                    or content_identity(os.fstat(checked_descriptors[-1])) != content_identity(after)
                    or any(runtime_identity(os.fstat(fd)) != entry[0] or runtime_mount(fd) != entry[1]
                           for fd, entry in zip(descriptors, before))):
                raise ValueError("runtime image path or mount changed during observation")
        finally:
            for descriptor in reversed(checked_descriptors):
                os.close(descriptor)
        return {"path": path, "mapped_identity": expected, "bytes": total,
                "sha256": digest.hexdigest(), "file_identity": content_identity(after), "ancestry": before}
    finally:
        if opened is not None:
            os.close(opened)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def observe_runtime():
    if platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("unsupported runtime ELF architecture")
    # Warm the digest provider before taking the loaded-image snapshot.
    hashlib.sha256(b"").digest()
    deadline = time.monotonic() + RUNTIME_OBSERVE_SECONDS
    before, images = runtime_maps()
    executable = os.open("/proc/self/exe", os.O_PATH | os.O_CLOEXEC)  # Trusted kernel magic link.
    try:
        value = os.fstat(executable)
        identity = os.major(value.st_dev), os.minor(value.st_dev), value.st_ino
        path = os.readlink("/proc/self/exe")
        runtime_path(path)
        if identity not in images or images[identity] != path:
            raise ValueError("interpreter executable is not bound to mapped runtime")
        observations, total = [], 0
        for key, name in sorted(images.items()):
            if time.monotonic() >= deadline:
                raise ValueError("runtime observation deadline reached")
            observed = runtime_image(name, key, deadline)
            total += observed["bytes"]
            if total > RUNTIME_TOTAL_BYTES:
                raise ValueError("runtime image batch exceeds its byte bound")
            observations.append(observed)
        after, final_images = runtime_maps()
        if (before != after or images != final_images or os.readlink("/proc/self/exe") != path
                or runtime_identity(os.fstat(executable)) != runtime_identity(value)
                or time.monotonic() >= deadline):
            raise ValueError("loaded runtime changed during file observation")
        return {"images": observations, "interpreter_path": path, "interpreter_identity": identity,
                "total_bytes": total, "native_runtime_authenticated": False,
                "memory_contents_attested": False, "dependency_closure_complete": False,
                "installation_authorized": False, "server_ready": False}
    finally:
        os.close(executable)
"""Native MDWE admission and live challenges; no code bytes are executed."""

import ctypes
import errno
import os
import platform


def protect_memory():
    if (platform.machine() not in ("x86_64", "aarch64")
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8):
        raise ValueError("unsupported MDWE native architecture or ABI")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    state = libc.prctl(66, 0, 0, 0, 0)  # PR_GET_MDWE
    if state < 0:
        raise OSError(ctypes.get_errno(), "MDWE query refused")
    if state not in (0, 1):
        # Refuse NO_INHERIT/unknown flags; never weaken an inherited policy.
        raise ValueError("unsupported inherited MDWE mask")
    size = os.sysconf("SC_PAGE_SIZE")
    if not 4096 <= size <= 65536 or size & (size - 1):
        raise ValueError("unsupported MDWE challenge page size")
    failed = ctypes.c_void_p(-1).value
    writable = libc.mmap(None, size, 3, 0x22, -1, 0)  # Private anonymous R/W.
    if writable == failed:
        raise OSError(ctypes.get_errno(), "MDWE writable-page baseline refused")
    try:
        if libc.mprotect(writable, size, 3) != 0:
            raise OSError(ctypes.get_errno(), "MDWE writable-page baseline protection refused")
        if libc.prctl(65, 1, 0, 0, 0) != 0:  # PR_SET_MDWE/REFUSE_EXEC_GAIN, inheritable.
            raise OSError(ctypes.get_errno(), "MDWE installation refused")
        if libc.prctl(66, 0, 0, 0, 0) != 1:
            raise RuntimeError("MDWE protection mask was not observed")
        ctypes.set_errno(0)
        if libc.mprotect(writable, size, 5) != -1 or ctypes.get_errno() != errno.EACCES:
            raise RuntimeError("MDWE execute-gain challenge failed")
        ctypes.set_errno(0)
        created = libc.mmap(None, size, 7, 0x22, -1, 0)
        observed_errno = ctypes.get_errno()
        if created != failed:
            if libc.munmap(created, size) != 0:
                raise OSError(ctypes.get_errno(), "MDWE unexpected-page cleanup refused")
            raise RuntimeError("MDWE writable-executable challenge failed")
        if observed_errno != errno.EACCES:
            raise RuntimeError("MDWE writable-executable challenge failed")
        if libc.mprotect(writable, size, 3) != 0:
            raise OSError(ctypes.get_errno(), "MDWE data-page compatibility refused")
        if libc.prctl(66, 0, 0, 0, 0) != 1:
            raise RuntimeError("MDWE final protection mask was not observed")
    finally:
        if libc.munmap(writable, size) != 0:
            raise OSError(ctypes.get_errno(), "MDWE challenge cleanup refused")
    return 1
"""Final descriptor duplication/mutation refusal and nonmutating witnesses."""

import ctypes
import errno
import os


DESCRIPTOR_DENIED = ("dup", "dup2", "dup3")


def add_descriptor_rules(lib, context):
    if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8:
        raise ValueError("unsupported descriptor native ABI")
    number = lib.seccomp_syscall_resolve_name(b"fcntl")
    if number == -1:
        raise ValueError("unknown syscall: fcntl")
    # Allow only exact F_GETFD=1/F_GETFL=3. Separate single-argument rules
    # avoid unsupported repeated comparisons on one argument. Full-width
    # comparisons also refuse high-bit aliases of kernel-truncated commands.
    for operation, value in ((2, 1), (4, 2), (6, 3)):  # LT1, EQ2, GT3.
        comparison = Comparison(1, operation, value, 0)
        checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                           number, 1, ctypes.byref(comparison)))


def verify_descriptors(descriptors):
    if (len(descriptors) != 2
            or any(type(fd) is not int or not 0 <= fd <= 0x7fffffff for fd in descriptors)
            or len(set(descriptors)) != 2):
        raise ValueError("two distinct descriptor observations are required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.dup.argtypes, libc.dup.restype = [ctypes.c_int], ctypes.c_int
    libc.dup2.argtypes, libc.dup2.restype = [ctypes.c_int, ctypes.c_int], ctypes.c_int
    libc.dup3.argtypes, libc.dup3.restype = [ctypes.c_int] * 3, ctypes.c_int
    libc.fcntl.argtypes, libc.fcntl.restype = [ctypes.c_int, ctypes.c_int, ctypes.c_long], ctypes.c_int
    # Invalid source FDs make all probes noncreating/nonmutating even when
    # a rule is absent. EBADF/EINVAL cannot certify the filter's EPERM.
    challenges = (
        ("dup", libc.dup, (-1,)),
        ("dup2", libc.dup2, (-1, -1)),
        ("dup3", libc.dup3, (-1, -1, 0)),
        ("fcntl-dupfd", libc.fcntl, (-1, 0, 0)),
        ("fcntl-setfd", libc.fcntl, (-1, 2, 0)),
        ("fcntl-setfl", libc.fcntl, (-1, 4, 0)),
        ("fcntl-dupfd-cloexec", libc.fcntl, (-1, 1030, 0)),
    )
    for name, operation, arguments in challenges:
        ctypes.set_errno(0)
        if operation(*arguments) != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("descriptor denial challenge failed: " + name)
    for descriptor in descriptors:
        flags = libc.fcntl(descriptor, 1, 0)
        status = libc.fcntl(descriptor, 3, 0)
        if flags not in (0, 1) or status < 0 or not status & os.O_NONBLOCK:
            raise RuntimeError("descriptor query/nonblocking state refused")
"""Checked child-only descriptor budgets and final resource-setter refusal."""

import ctypes
import errno
import platform
import resource


FD_STARTUP_LIMIT = 256
FD_FORWARD_LIMIT = 16
RESOURCE_DENIED = ("setrlimit",)


class ResourceLimit64(ctypes.Structure):
    _fields_ = [("current", ctypes.c_uint64), ("maximum", ctypes.c_uint64)]


def resource_abi():
    if (platform.machine() not in ("x86_64", "aarch64")
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_ulong) != 8
            or resource.RLIMIT_NOFILE != 7):
        raise ValueError("unsupported resource native ABI")


def bound_descriptors(ceiling, retained=()):
    resource_abi()
    if ceiling not in (FD_STARTUP_LIMIT, FD_FORWARD_LIMIT):
        raise ValueError("unsupported descriptor resource budget")
    if any(type(fd) is not int or not 0 <= fd <= 0x7fffffff for fd in retained):
        raise ValueError("invalid retained descriptor observation")
    observed = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (not isinstance(observed, tuple) or len(observed) != 2
            or any(type(value) is not int or (value != resource.RLIM_INFINITY and not 0 <= value < 1 << 64)
                   for value in observed)):
        raise ValueError("descriptor resource observations refused")
    normalized = tuple((1 << 64) - 1 if value == resource.RLIM_INFINITY else value for value in observed)
    if normalized[0] > normalized[1]:
        raise ValueError("descriptor resource observations refused")
    expected = tuple(min(value, ceiling) for value in normalized)
    # RLIMIT_NOFILE does not close already-open high descriptors. The caller
    # scrubs extras first, and every kept channel must be below the new bound.
    if any(fd >= expected[0] for fd in retained):
        raise ValueError("retained descriptor exceeds resource budget")
    resource.setrlimit(resource.RLIMIT_NOFILE, expected)
    if resource.getrlimit(resource.RLIMIT_NOFILE) != expected:
        raise RuntimeError("descriptor resource limit was not observed")
    return expected


def add_resource_rules(lib, context):
    resource_abi()
    number = lib.seccomp_syscall_resolve_name(b"prlimit64")
    if number == -1:
        raise ValueError("unknown syscall: prlimit64")
    # NULL new_limit means query only. Compare pointer presence, never its
    # contents: every non-NULL update request is denied for every resource/PID.
    comparison = Comparison(2, 1, 0, 0)  # SCMP_CMP_NE, new_limit != NULL.
    checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                       number, 1, ctypes.byref(comparison)))


def native_resource_api():
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        libc.prlimit64.argtypes = [ctypes.c_int, ctypes.c_int,
                                  ctypes.POINTER(ResourceLimit64), ctypes.POINTER(ResourceLimit64)]
        libc.prlimit64.restype = ctypes.c_int
        libc.syscall.argtypes, libc.syscall.restype = [ctypes.c_long], ctypes.c_long
    except AttributeError as error:
        raise ValueError("native resource interfaces unavailable") from error
    return libc


def verify_resource_limits(expected):
    resource_abi()
    if (not isinstance(expected, tuple) or len(expected) != 2
            or any(type(value) is not int for value in expected)
            or not 0 < expected[0] <= expected[1] <= FD_FORWARD_LIMIT):
        raise ValueError("invalid forwarding descriptor budget")
    if resource.getrlimit(resource.RLIMIT_NOFILE) != expected:
        raise RuntimeError("descriptor resource read-back refused")
    libc = native_resource_api()
    observed = ResourceLimit64()
    if (libc.prlimit64(0, 7, None, ctypes.byref(observed)) != 0
            or (observed.current, observed.maximum) != expected):
        raise RuntimeError("native descriptor resource query refused")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes, lib.seccomp_syscall_resolve_name.restype = [ctypes.c_char_p], ctypes.c_int
    invalid = ResourceLimit64(0, 0)
    # Raw syscalls avoid libc setrlimit being redirected through prlimit64.
    # Resource -1 is invalid even if a filter rule is absent; no limit changes.
    probes = (
        ("setrlimit", (ctypes.c_long(-1), ctypes.byref(invalid))),
        ("prlimit64", (ctypes.c_long(0), ctypes.c_long(-1), ctypes.byref(invalid), ctypes.c_void_p())),
    )
    for name, arguments in probes:
        number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        if number == -1:
            raise ValueError("unknown resource syscall: " + name)
        ctypes.set_errno(0)
        if libc.syscall(ctypes.c_long(number), *arguments) != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("resource setter challenge failed: " + name)
    if (resource.getrlimit(resource.RLIMIT_NOFILE) != expected
            or libc.prlimit64(0, 7, None, ctypes.byref(observed)) != 0
            or (observed.current, observed.maximum) != expected):
        raise RuntimeError("descriptor resource budget changed during challenges")


BACKEND_USER = "azurelinux3s4-web-backend"
PROXY_USER = "azurelinux3s4-web-proxy"
SHARED_GROUP = "azurelinux3s4-web"
ROOT_UID = 0
ROOT_GID = 0
JOURNAL = "/run/systemd/journal/stdout"
BUFFER = 65536
IDLE_SECONDS = 30
TOTAL_SECONDS = 300
METADATA_DENIED = (
    # Landlock filesystem rights do not cover these metadata mutations.
    "chmod", "fchmod", "fchmodat", "fchmodat2",
    "chown", "fchown", "lchown", "fchownat",
    "utime", "utimes", "futimesat", "utimensat",
    "setxattr", "lsetxattr", "fsetxattr",
    "removexattr", "lremovexattr", "fremovexattr",
)
IPC_DENIED = (
    # No signal delivery, SysV/POSIX named IPC or kernel key operations are
    # needed for read/write forwarding. Incoming supervisor signals still work.
    "kill", "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_send_signal",
    "semget", "semop", "semtimedop", "semctl",
    "msgget", "msgsnd", "msgrcv", "msgctl",
    "shmget", "shmat", "shmdt", "shmctl",
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr",
    "add_key", "request_key", "keyctl",
)
DENIED = (
    "socket", "socketpair", "connect", "accept", "accept4",
    # Fast Open through sendto/sendmsg is also a connection initiation route.
    # Forward through read/write only; never permit caller-controlled flags.
    "sendto", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "setsockopt", "ioctl",
    "pidfd_getfd", "io_uring_setup", "io_uring_enter", "io_uring_register", "bpf",
    "execve", "execveat", "clone", "clone3", "fork", "vfork", "unshare", "setns",
    "ptrace", "process_vm_readv", "process_vm_writev",
) + METADATA_DENIED + IPC_DENIED + DESCRIPTOR_DENIED + RESOURCE_DENIED


class Comparison(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]


def peer_credentials(stream):
    # SO_PEERCRED is a connect/listen-time observation, not executable identity
    # or evidence that the currently executing process still has these IDs.
    data = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    if len(data) != 12:
        raise ValueError("Unix peer credentials are incomplete")
    pid, uid, gid = struct.unpack("=iII", data)
    if pid <= 0 or uid == 0xffffffff or gid == 0xffffffff:
        raise ValueError("Unix peer credentials are unavailable")
    return pid, uid, gid


def process_identity():
    proxy = pwd.getpwnam(PROXY_USER)
    backend = pwd.getpwnam(BACKEND_USER)
    group = grp.getgrnam(SHARED_GROUP)
    if (proxy.pw_name != PROXY_USER or backend.pw_name != BACKEND_USER
            or group.gr_name != SHARED_GROUP
            or not 0 < proxy.pw_uid < 0xffffffff
            or not 0 < backend.pw_uid < 0xffffffff
            or proxy.pw_uid == backend.pw_uid
            or not 0 < group.gr_gid < 0xffffffff
            or pwd.getpwuid(proxy.pw_uid).pw_name != PROXY_USER
            or pwd.getpwuid(backend.pw_uid).pw_name != BACKEND_USER
            or grp.getgrgid(group.gr_gid).gr_name != SHARED_GROUP):
        raise ValueError("dedicated web account observations are inconsistent")
    if (os.getresuid() != (proxy.pw_uid,) * 3
            or os.getresgid() != (group.gr_gid,) * 3
            or not set(os.getgroups()) <= {group.gr_gid}):
        raise ValueError("web worker credentials differ from the dedicated identity")
    # Root, borrowed supplementary groups and retained capabilities are refused.
    # NSS/base/procfs are trusted inputs; this is not account creation/admission.
    with open("/proc/self/status", "rb") as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        raise ValueError("process status exceeds the observation bound")
    records = {}
    for line in data.splitlines():
        key, separator, value = line.partition(b":")
        if separator and key in (b"Uid", b"Gid", b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb", b"NoNewPrivs"):
            if key in records:
                raise ValueError("duplicate process status observation")
            records[key] = value.split()
    if (records.get(b"Uid") != [str(proxy.pw_uid).encode()] * 4
            or records.get(b"Gid") != [str(group.gr_gid).encode()] * 4
            or records.get(b"NoNewPrivs") != [b"1"]):
        raise ValueError("process filesystem IDs or NNP observation refused")
    for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        values = records.get(key, [])
        if len(values) != 1 or len(values[0]) != 16 or values[0] != b"0" * 16:
            raise ValueError("process capability observation refused")
    return proxy.pw_uid, backend.pw_uid, group.gr_gid


def admit_logging():
    observations = []
    for descriptor in (1, 2):
        if not stat.S_ISSOCK(os.fstat(descriptor).st_mode):
            raise ValueError("only connected Unix journal logging descriptors are accepted")
        stream = socket.socket(fileno=descriptor)
        try:
            if (stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM
                    or stream.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                    or stream.getpeername() != JOURNAL):
                raise ValueError("unexpected journal descriptor")
            peer = peer_credentials(stream)
            if peer[1:] != (ROOT_UID, ROOT_GID):
                raise ValueError("journal peer is not the expected root identity")
            observations.append(peer)
        finally:
            stream.detach()
    if observations[0] != observations[1]:
        raise ValueError("journal descriptors have different peers")


def inode_identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def mount_identity(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb") as stream:
        data = stream.read(8193)
    if len(data) > 8192:
        raise ValueError("descriptor mount observation exceeds the bound")
    values = [line.split(b":", 1)[1].strip() for line in data.splitlines()
              if line.startswith(b"mnt_id:")]
    if len(values) != 1 or not values[0].isdigit():
        raise ValueError("descriptor mount identity is unavailable")
    return int(values[0])


def backend_root():
    return os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def backend_path(backend_uid, group_gid):
    # Fixed, alias-free path. O_PATH never opens a FIFO/device/socket for IO;
    # NOFOLLOW leaves symlinks as links so they cannot redirect this walk.
    descriptors = []
    try:
        root = backend_root()
        descriptors.append(root)
        trace = []
        for index, name in enumerate((None, "run", "azurelinux3s4-web", "http.sock")):
            if name is not None:
                descriptors.append(os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=descriptors[-1]))
            descriptor = descriptors[-1]
            value = os.fstat(descriptor)
            if index < 2:
                if not stat.S_ISDIR(value.st_mode) or value.st_uid != ROOT_UID or value.st_mode & 0o022:
                    raise ValueError("unprotected backend root or run ancestry")
            elif index == 2:
                if (not stat.S_ISDIR(value.st_mode) or value.st_uid != backend_uid
                        or value.st_gid != group_gid or stat.S_IMODE(value.st_mode) != 0o750):
                    raise ValueError("backend runtime directory identity or permissions refused")
            elif (not stat.S_ISSOCK(value.st_mode) or value.st_uid != backend_uid
                  or value.st_gid != group_gid or stat.S_IMODE(value.st_mode) != 0o666):
                raise ValueError("backend socket identity, kind or permissions refused")
            trace.append((inode_identity(value), mount_identity(descriptor)))
        # RuntimeDirectory may be a checked read-only bind in the worker. The
        # socket must be on that same mount; parent transitions are rechecked.
        if trace[-1][1] != trace[-2][1]:
            raise ValueError("backend socket has a separate mount")
        return descriptors, trace
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def connect_backend(backend_uid, group_gid):
    descriptors, before = backend_path(backend_uid, group_gid)
    connection = None
    try:
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(5)
        # Resolve the held socket inode through the trusted kernel fd link,
        # rather than reopening its original pathname for connection setup.
        connection.connect(f"/proc/self/fd/{descriptors[-1]}")
        peer = peer_credentials(connection)
        if peer[1:] != (backend_uid, group_gid):
            raise ValueError("backend listener credentials do not match the socket owner")
        after_descriptors, after = backend_path(backend_uid, group_gid)
        try:
            if before != after or any(inode_identity(os.fstat(fd)) != item[0]
                                      or mount_identity(fd) != item[1]
                                      for fd, item in zip(descriptors, before)):
                raise ValueError("backend ancestry/socket changed during admission")
        finally:
            for descriptor in reversed(after_descriptors):
                os.close(descriptor)
        if peer_credentials(connection) != peer:
            raise ValueError("backend peer credentials changed during admission")
        connection.setblocking(False)
        return connection
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def checked(result):
    if result < 0:
        raise OSError(-result, "relay seccomp operation refused")


def restrict(final):
    if platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("unsupported native architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "no-new-privileges refused")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                         ctypes.c_uint, ctypes.POINTER(Comparison)]
    lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint32]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7fff0000)  # ALLOW; native ABI only, bad ABI kills.
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        checked(lib.seccomp_attr_set(context, 4, 1))  # CTL_TSYNC, all current threads
        checked(lib.seccomp_attr_set(context, 2, 0x80000000))  # ACT_BADARCH: KILL_PROCESS
        if final:
            for name in DENIED:
                number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
                if number == -1:  # __NR_SCMP_ERROR; other negative values are pseudo IDs.
                    raise ValueError("unknown syscall: " + name)
                checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM, number, 0, None))
            add_descriptor_rules(lib, context)
            add_resource_rules(lib, context)
        else:
            number = lib.seccomp_syscall_resolve_name(b"socket")
            if number == -1:
                raise ValueError("socket syscall unknown")
            for operation in (2, 6):  # SCMP_CMP_LT, GT: only AF_UNIX can be created.
                comparison = Comparison(0, operation, socket.AF_UNIX, 0)
                checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EAFNOSUPPORT,
                                                   number, 1, ctypes.byref(comparison)))
        checked(lib.seccomp_load(context))
        if libc.prctl(39, 0, 0, 0, 0) != 1 or libc.prctl(21, 0, 0, 0, 0) != 2:
            raise RuntimeError("kernel did not report NNP/filter mode")
    finally:
        lib.seccomp_release(context)


def verify_seal(connection):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    address = ctypes.create_string_buffer(16)  # Actual AF_UNSPEC disconnect challenge.
    if libc.connect(connection.fileno(), address, 16) != -1 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("connect denial challenge failed")
    try:
        created = socket.socket(socket.AF_UNIX)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        created.close()
        raise RuntimeError("socket denial challenge failed")
    connection.getpeername()  # The challenge must leave the accepted connection intact.


def verify_operations():
    # These calls cannot modify files, deliver a signal or create an IPC/key
    # object even if a rule is missing. Require the filter's EPERM rather than
    # the ordinary invalid-FD/argument error or successful signal-zero query.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.argtypes = [ctypes.c_long]
    libc.syscall.restype = ctypes.c_long
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    challenges = (
        ("fchmod", (-1, 0)),
        ("kill", (os.getpid(), 0)),
        ("shmget", (0, 0, 0)),
        ("mq_getsetattr", (-1, 0, 0)),
        ("keyctl", (-1, 0, 0, 0, 0)),
    )
    for name, arguments in challenges:
        number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        if number < 0:
            raise ValueError("operation challenge syscall unavailable: " + name)
        ctypes.set_errno(0)
        result = libc.syscall(ctypes.c_long(number), *(ctypes.c_long(value) for value in arguments))
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("operation denial challenge failed: " + name)


def confine_filesystem():
    # No allow rules: deny every known handled filesystem right. ABI3 adds
    # truncate, ABI5 device ioctl. Later network/scope fields stay zero. This
    # is a calling-thread layer; final TSYNC clone denial must precede the
    # single-task check. Metadata/O_PATH and already-open FDs remain separate.
    if (platform.machine() not in ("x86_64", "aarch64")
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8):
        raise ValueError("unsupported Landlock native architecture or ABI")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.argtypes = [ctypes.c_long]
    libc.syscall.restype = ctypes.c_long
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(39, 0, 0, 0, 0) != 1 or libc.prctl(21, 0, 0, 0, 0) != 2:
        raise RuntimeError("filesystem confinement requires NNP and seccomp")
    # Linux x86_64 and asm-generic/aarch64 use these native syscall numbers.
    abi = libc.syscall(ctypes.c_long(444), ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint(1))
    if abi < 0:
        raise OSError(ctypes.get_errno(), "Landlock ABI query refused")
    if abi < 3:
        raise ValueError("Landlock ABI3 or newer is required")
    with os.scandir("/proc/self/task") as tasks:
        observed = [entry.name for _, entry in zip(range(2), tasks)]
    if observed != [str(os.getpid())]:
        raise RuntimeError("filesystem confinement requires one live task")
    rights = (1 << 15) - 1
    if abi >= 5:
        rights |= 1 << 15
    attribute = ctypes.c_uint64(rights)  # Eight-byte handled_access_fs prefix.
    probe = os.open("/proc/self/status", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(probe).st_mode) or not os.read(probe, 1):
            raise ValueError("filesystem read challenge has no regular readable baseline")
        ruleset = libc.syscall(ctypes.c_long(444), ctypes.byref(attribute),
                               ctypes.c_size_t(ctypes.sizeof(attribute)), ctypes.c_uint(0))
        if ruleset < 0:
            raise OSError(ctypes.get_errno(), "Landlock ruleset creation refused")
        try:
            if libc.syscall(ctypes.c_long(446), ctypes.c_int(ruleset), ctypes.c_uint(0)) != 0:
                raise OSError(ctypes.get_errno(), "Landlock restriction refused")
        finally:
            os.close(ruleset)
        # Check both the namespace path and trusted kernel fd-link reopening.
        # Only EACCES after a successful baseline certifies this challenge.
        for path in ("/proc/self/status", f"/proc/self/fd/{probe}"):
            try:
                opened = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            except OSError as error:
                if error.errno != errno.EACCES:
                    raise
            else:
                os.close(opened)
                raise RuntimeError("filesystem read-denial challenge failed")
    finally:
        os.close(probe)
    return abi, rights


def forward(client, backend):
    # At most two BUFFER-sized queues; half-close each destination only after
    # its queued data drains. No connection setup, recvmsg or flagged send calls.
    streams = {client.fileno(): backend.fileno(), backend.fileno(): client.fileno()}
    objects = {stream.fileno(): stream for stream in (client, backend)}
    buffers = {descriptor: bytearray() for descriptor in streams}
    readable = set(streams)
    write_open = set(streams)
    started = last_progress = time.monotonic()
    with selectors.DefaultSelector() as selector:
        registered = set()
        while readable or any(buffers.values()):
            now = time.monotonic()
            remaining = min(started + TOTAL_SECONDS - now, last_progress + IDLE_SECONDS - now)
            if remaining <= 0:
                raise TimeoutError("relay connection deadline reached")
            for descriptor, destination in streams.items():
                events = 0
                if descriptor in readable and len(buffers[destination]) < BUFFER:
                    events |= selectors.EVENT_READ
                if buffers[descriptor]:
                    events |= selectors.EVENT_WRITE
                if events:
                    if descriptor in registered:
                        selector.modify(descriptor, events)
                    else:
                        selector.register(descriptor, events)
                        registered.add(descriptor)
                elif descriptor in registered:
                    selector.unregister(descriptor)
                    registered.remove(descriptor)
            for key, events in selector.select(remaining):
                descriptor = key.fd
                destination = streams[descriptor]
                if events & selectors.EVENT_READ:
                    try:
                        data = os.read(descriptor, BUFFER - len(buffers[destination]))
                    except BlockingIOError:
                        pass
                    else:
                        if data:
                            buffers[destination].extend(data)
                            last_progress = time.monotonic()
                        else:
                            readable.remove(descriptor)
                if events & selectors.EVENT_WRITE:
                    try:
                        count = os.write(descriptor, buffers[descriptor])
                    except BlockingIOError:
                        pass
                    else:
                        if count <= 0:
                            raise OSError("relay write made no progress")
                        del buffers[descriptor][:count]
                        last_progress = time.monotonic()
            for source, destination in streams.items():
                if source not in readable and not buffers[destination] and destination in write_open:
                    objects[destination].shutdown(socket.SHUT_WR)
                    write_open.remove(destination)


def prepare_client(descriptor):
    connection = socket.socket(fileno=descriptor)
    try:
        if (connection.family not in (socket.AF_INET, socket.AF_INET6)
                or connection.type != socket.SOCK_STREAM
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError("an accepted IPv4/IPv6 stream is required")
        connection.getpeername()
        # Avoid implicit connection initiation from ordinary writes. Linux ABI:
        # TCP_FASTOPEN_CONNECT=30. An established socket cannot change this
        # option: observe zero, otherwise refuse. Sealing also denies setsockopt.
        if connection.getsockopt(socket.IPPROTO_TCP, 30) != 0:
            raise ValueError("Fast Open connect remains enabled")
        connection.setblocking(False)
        return connection
    except BaseException:
        connection.close()
        raise


def close_inherited():
    for descriptor in (1, 2):
        if stat.S_ISSOCK(os.fstat(descriptor).st_mode):
            stream = socket.socket(fileno=descriptor)
            try:
                if stream.family != socket.AF_UNIX:
                    raise ValueError("stdout/stderr cannot be inherited IP sockets")
            finally:
                stream.detach()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    if libc.close_range(3, 0xffffffff, 0):
        raise OSError(ctypes.get_errno(), "cannot close extra inherited descriptors")


def close_runtime_extras(backend):
    # NSS/native libraries may retain descriptors during startup. Keep only
    # stdio and the checked backend, even after the final account lookup.
    descriptor = backend.fileno()
    if descriptor < 3:
        raise ValueError("backend descriptor overlaps standard IO")
    before = inode_identity(os.fstat(descriptor))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    for first, last in ((3, descriptor - 1), (descriptor + 1, 0xffffffff)):
        if first <= last and libc.close_range(first, last, 0):
            raise OSError(ctypes.get_errno(), "cannot close startup lookup/extra descriptors")
    if inode_identity(os.fstat(descriptor)) != before:
        raise ValueError("backend descriptor changed during extra descriptor closure")


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("no relay overrides are accepted")
        resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        with RuntimeStartup() as startup:
            credentials = process_identity()
            admit_logging()
            close_inherited()
            bound_descriptors(FD_STARTUP_LIMIT)
            with prepare_client(0) as client:
                restrict(False)
                with connect_backend(credentials[1], credentials[2]) as backend:
                    if process_identity() != credentials:
                        raise ValueError("web account observations changed during startup")
                    observe_runtime()
                    protect_memory()
                    close_runtime_extras(backend)
                    descriptor_budget = bound_descriptors(FD_FORWARD_LIMIT, (0, 1, 2, backend.fileno()))
                    restrict(True)
                    verify_seal(client)
                    verify_operations()
                    verify_descriptors((client.fileno(), backend.fileno()))
                    verify_resource_limits(descriptor_budget)
                    confine_filesystem()
                    startup.disarm()
                    forward(client, backend)
    except (OSError, ValueError, RuntimeError, MemoryError, KeyError) as error:
        print("Web relay refused: " + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''.removeprefix("\n")
"""Emit candidate HTTP isolation files without installing or activating them."""

import hashlib
import json
import resource
import sys


BACKEND = "azurelinux3s4-web-backend"
PROXY = "azurelinux3s4-web"
GROUP = "azurelinux3s4-web"
RUNTIME = "/run/azurelinux3s4-web"
CONFIG = "/etc/azurelinux3s4/web/nginx.conf"
CONTENT = "/srv/azurelinux3s4/www"
RELAY = "/usr/local/lib/azurelinux3s4/web-relay.py"

COMMON = """DynamicUser=yes
Group=azurelinux3s4-web
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
PrivateDevices=yes
PrivateTmp=yes
PrivateIPC=yes
ProtectSystem=strict
ProtectHome=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RemoveIPC=yes
UMask=0077
SystemCallFilter=~@mount @reboot @swap @raw-io @debug bpf keyctl add_key request_key io_uring_setup io_uring_enter io_uring_register
SystemCallErrorNumber=EPERM
TasksMax=64
MemoryMax=256M
LimitNOFILE=1024
TimeoutStartSec=30s
TimeoutStopSec=30s
KillMode=control-group
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
"""


def files():
    if not isinstance(globals().get("RELAY_SOURCE"), str) or not RELAY_SOURCE:
        raise ValueError("the assembled relay payload is required")
    # These are separate units: vendor nginx.service and its configuration are
    # never rewritten. A future applier must refuse conflicting existing units.
    backend = f"""[Unit]
Description=Isolated Azure Linux 3 static HTTP backend
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=forking
Slice=azurelinux3s4-web.slice
User={BACKEND}
{COMMON}RuntimeDirectory=azurelinux3s4-web
RuntimeDirectoryMode=0750
PIDFile={RUNTIME}/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -c {CONFIG}
ExecStart=/usr/sbin/nginx -c {CONFIG}
ExecReload=/bin/kill -s HUP $MAINPID
KillSignal=SIGQUIT
SystemCallFilter=~connect
"""
    proxy = f"""[Unit]
Description=One accepted Azure Linux 3 HTTP connection candidate
CollectMode=inactive-or-failed
Requires={PROXY}.socket
BindsTo={BACKEND}.service
After={PROXY}.socket {BACKEND}.service
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=exec
Slice=azurelinux3s4-web.slice
User=azurelinux3s4-web-proxy
{COMMON}Restart=no
# 60s worker startup + 300s forwarding + 30s loader/local cleanup reserve.
RuntimeMaxSec=390s
StandardInput=socket
ExecStart=/usr/bin/python3 -I {RELAY}
# Hide host runtime sockets; expose the backend and dynamic identity lookup only.
TemporaryFileSystem=/run:ro /var:ro
BindReadOnlyPaths={RUNTIME}
BindReadOnlyPaths=/run/systemd/userdb/io.systemd.DynamicUser
InaccessiblePaths=/etc/azurelinux3s4
# Startup permits the one Unix connect. The worker must seal connect, flagged
# sends, socket/FD acquisition and process creation BEFORE forwarding any bytes.
SystemCallFilter=~recvmsg recvmmsg pidfd_getfd
"""
    listener = f"""[Unit]
Description=Azure Linux 3 HTTP ingress candidate

[Socket]
ListenStream=0.0.0.0:80
ListenStream=[::]:80
BindIPv6Only=ipv6-only
Accept=yes
MaxConnections=32
Backlog=256

[Install]
WantedBy=sockets.target
"""
    nginx = f"""daemon on;
master_process on;
worker_processes 1;
pid {RUNTIME}/nginx.pid;
error_log stderr warn;
events {{
    worker_connections 512;
}}
http {{
    access_log /dev/stdout;
    server_tokens off;
    default_type application/octet-stream;
    sendfile on;
    autoindex off;
    disable_symlinks on;
    client_max_body_size 1m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 30s;
    keepalive_timeout 15s;
    client_body_temp_path {RUNTIME}/client-body;
    proxy_temp_path {RUNTIME}/proxy;
    fastcgi_temp_path {RUNTIME}/fastcgi;
    uwsgi_temp_path {RUNTIME}/uwsgi;
    scgi_temp_path {RUNTIME}/scgi;
    server {{
        listen unix:{RUNTIME}/http.sock;
        server_name _;
        root {CONTENT};
        location / {{
            try_files $uri $uri/ =404;
        }}
    }}
}}
"""
    return {
        "systemd/" + BACKEND + ".service": backend,
        "systemd/" + PROXY + "@.service": proxy,
        "systemd/" + PROXY + ".socket": listener,
        "nginx/nginx.conf": nginx,
        "sysusers/azurelinux3s4-web.conf": "g " + GROUP + " -\n",
        "systemd/azurelinux3s4-web.slice": """[Unit]
Description=Azure Linux 3 web aggregate resource candidate

[Slice]
MemoryMax=512M
MemorySwapMax=0
TasksMax=128
CPUQuota=100%
""",
        # RELAY_SOURCE is supplied by the explicit assembly before this payload.
        # Source-level tests supply the same maintained bytes, never an env value.
        "lib/web-relay.py": RELAY_SOURCE,
    }


def bundle():
    candidates = []
    for name, content in sorted(files().items()):
        data = content.encode("utf-8")
        candidates.append({"file": name, "mode": "0644", "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest(), "content": content})
    # Emission proves candidate bytes only. Never equate a generated directive
    # with its actual enforcement, a listener, TLS, or completed host isolation.
    return {
        "schema": 1, "profile": "static-http-unix-backend", "files": candidates,
        "authority": {name: False for name in (
            "files_installed", "accounts_created", "packages_installed", "units_activated",
            "kernel_enforcement_verified", "nginx_configuration_tested", "proxy_egress_restricted",
            "inherited_inet_sockets_restricted", "lan_containment_verified", "tls_ready", "server_ready")},
        "prerequisites": [
            "Fresh authenticated nginx/systemd runtime and supported native x86_64/aarch64 ABI.",
            "Root-owned protected configuration/content and conflict-admitted dedicated UID/GID/shared-group allocation; name-service observations alone do not authorize identities.",
            "Conflict-safe durable installation, actual parser tests and boot/repair ownership.",
            "Positive network namespace/seccomp/filesystem/capability enforcement challenges.",
            "Independent proxy egress protection covering inherited TCP sockets, with positive refusal challenges.",
            "Trusted Python/libseccomp/close_range and per-connection worker sealing BEFORE forwarding, including connect/Fast Open/FD-acquisition refusals and same-connection byte/half-close proof.",
            "Only the accepted stdin TCP socket and connected root journal logging descriptors may be inherited; verify aggregate slice/MaxConnections and per-worker limits.",
            "Native SAME-byte worker credential, protected backend ancestry/held socket and peer-credential admission, with conflict-safe caller/manager authorization independent of names or PIDs; trusted NSS and the single dynamic identity lookup socket must be available.",
            "Enabled native Landlock ABI3+; final TSYNC process-creation denial and one live task before an empty filesystem ruleset, successful native installation and namespace/fd-link read-denial challenges BEFORE forwarding.",
            "Native libseccomp must resolve every denied metadata/signal/SysV/POSIX-mqueue/key syscall, including fchmodat2; checked EPERM challenges for each family must precede filesystem confinement and forwarding.",
            "Fresh mapped-runtime/interpreter inode/path/ELF/hash observations before final descriptor scrubbing; clean unblocked SIGALRM/default-handler/no-existing-timer context and checked 60s startup timer retired before forwarding.",
            "Native PR_SET_MDWE/PR_GET_MDWE with exact inheritable REFUSE_EXEC_GAIN mask1, actual writable-executable mmap and execute-gain mprotect EACCES challenges, preserved data-page operations and successful challenge cleanup before forwarding.",
            "Final native dup/dup2/dup3 denial and fcntl restricted to exact F_GETFD/F_GETFL queries; noncreating invalid-FD EPERM witnesses and both checked channel nonblocking/query observations before forwarding.",
            "Checked child-only RLIMIT_NOFILE startup ceiling256 and forwarding ceiling16, preserving stricter inherited bounds; kept descriptors below the bound, exact Python/native read-back, final setrlimit/prlimit64-update denial and invalid-resource EPERM witnesses.",
            "Current MAC, content/runtime access and capacity policy; native nginx/proxy lifecycle proof.",
            "HTTPS certificate provisioning/renewal, listener/firewall policy and client identity/rate controls.",
        ],
        "limits": [
            "Candidate HTTP files only; generation does not install, activate or inspect the host.",
            "The worker retains an inherited IP connection; socket creation restrictions alone do not stop reconnects. No activation or native Azure worker/unit enforcement is certified by emission.",
            "The worker checks dedicated process IDs/groups/NNP/zero capabilities, journal descriptors, protected fixed backend ancestry and a held socket inode plus connect/listen-time Unix peer IDs, scrubs lookup/extra descriptors, then seals before forwarding. The read-only dynamic identity socket bind does not make its IPC protocol read-only. These observations do not authenticate native runtime or current peer executable, authorize the caller, certify manager launch, prevent UID reuse or establish atomic/ABA/concurrent-root protection.",
            "The relay additionally denies all known Landlock filesystem rights after startup; ABI3 handles file read/write/execute, directory reads, namespace creation/removal/reparenting and truncation, with device ioctl on ABI5+. Missing support or a failed challenge refuses. Existing descriptor rights, metadata/O_PATH, shared mappings, other processes and backend nginx filesystem access are separate; kernel/base/runtime/procfs are trusted. This is a calling-thread layer after final TSYNC and a bounded single-task check, not whole-host or full MAC enforcement.",
            "The final native filter also refuses chmod/chown/timestamp/xattr mutations, outgoing signals, SysV IPC, POSIX mqueues and kernel keys through the explicitly named syscalls. Safe challenge arguments do not mutate files, deliver signals or allocate objects. Metadata observation/O_PATH, anonymous memory/IPC, futexes, existing mappings, allowed descriptor IO and future unnamed syscalls remain outside this bounded layer; incoming supervisor signals remain available. This is not complete IPC or host isolation.",
            "The worker observes already-loaded executable ELF files and its interpreter via trusted procfs, protected root-owned alias-free paths and same-inode hash descriptors. This is post-load file observation, not signed-package/native-runtime/memory attestation or complete Python/NSS/dependency/environment authentication. Deleted/ambiguous/unsupported maps or executable anonymous/writable mappings refuse; permitted heap/data mappings and future mappings remain separate. The 30s observer and 60s startup guards assume finite honest IO/scheduling; generated 390s runtime allowance includes 300s forwarding and a 30s loader/local reserve, with separate 30s stop grace. No universal stalled-kernel or native manager liveness is certified.",
            "The worker additionally sets and challenges native memory-deny-write-execute after runtime observation and before final descriptor scrubbing. Unsupported, non-inheriting/unknown masks, failed installation/read-back or any challenge/cleanup failure refuse. It denies new writable-executable mappings and execute gain from non-executable mappings, while fresh read-execute mappings and previously executable code remain possible. It does not revoke preexisting mappings, authenticate memory, prevent code reuse/all aliases or prove whole-process/host isolation. Kernel/native runtime and finite IO/scheduling remain trusted; emitted systemd MemoryDenyWriteExecute alone is not enforcement evidence.",
            "After final sealing, named descriptor duplication/replacement syscalls and every fcntl operation except exact descriptor/status flag queries are refused, including flag changes and duplication. Invalid-source witnesses cannot create or replace descriptors; actual channel queries must still report nonblocking IO. This does not prohibit all descriptor creation, close/reuse through every kernel interface, existing channel/logging IO, metadata/O_PATH access, aliases in other processes or resource exhaustion. Trusted kernel/runtime and separate complete descriptor/resource/outer policy remain prerequisites.",
            "The worker bounds its own descriptor numbers after inherited-FD closure and again after startup-FD closure. RLIMIT_NOFILE does not close existing high descriptors; all retained channels must fit. Lower inherited soft/hard limits are preserved and may cause a truthful refusal when the runtime cannot fit. Final sealing denies setrlimit and every prlimit64 request with a non-NULL new-limit pointer; read-only queries remain. This does not reserve slots, limit all kernel memory/anonymous objects or other processes, prevent a worker exhausting its own budget, or prove whole-service/host availability. Startup256 covers bounded paired runtime ancestry walks with finite local headroom, not arbitrary NSS/runtime compatibility or native manager enforcement.",
            "No nft_socket feature is assumed: Azure Linux3 x86 source config disables it. Host-wide firewall and non-web egress policy remain separate unfinished components.",
            "Pathname Unix sockets remain reachable across private network namespaces; privileged IPC policy needs verification.",
            "Static content only; no upstream, DNS, reverse proxy, .NET application or certificate lifecycle is configured.",
            "The byte-forwarding proxy does not preserve a trusted original client address at nginx.",
            "Responses to accepted clients remain possible; compromised host/root/kernel protection is not claimed.",
        ],
    }


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("no policy overrides are accepted")
        resource.setrlimit(resource.RLIMIT_CPU, (10, 15))
        resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = json.dumps(bundle(), sort_keys=True, separators=(",", ":")) + "\n"
        sys.stdout.write(result)
    except (OSError, ValueError, MemoryError) as error:
        print("Web policy emission failed: " + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
}

s4_ssh_policy() {
    # Candidate bytes only; no observation, package/account/key/file/service
    # installation. LAN/caller/key authorization remains a later prerequisite.
    timeout --kill-after=5s 30s python3 -I - <<'PY'
"""Compile standalone SSH candidate bytes; no account, key or service changes."""

import hashlib
import ipaddress
import json
import resource
import sys


ADMIN = "azurelinux3s4-admin"
DEFAULT_PREFIXES = ("127.0.0.1/32", "::1/128")
DEFAULT_LISTEN = ("127.0.0.1", "::1")
LOCAL_BOUNDS = tuple(ipaddress.ip_network(value) for value in (
    "127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def sources(prefixes, listeners):
    for values in (prefixes, listeners):
        if (not isinstance(values, (tuple, list)) or not 1 <= len(values) <= 64
                or any(not isinstance(value, str) or not value.isascii() or not value or len(value) > 64
                       or "%" in value or any(ord(character) < 33 or ord(character) > 126 for character in value)
                       for value in values)):
            raise ValueError("bounded explicit SSH prefixes and listeners are required")
    networks, addresses = [], []
    for value in prefixes:
        network = ipaddress.ip_network(value, strict=True)
        if (network.with_prefixlen != value or not any(network.version == bound.version and network.subnet_of(bound)
                                                     for bound in LOCAL_BOUNDS)):
            raise ValueError("SSH source prefix is not canonical loopback/private space")
        if any(network.version == previous.version and network.overlaps(previous) for previous in networks):
            raise ValueError("overlapping or repeated SSH source prefixes refused")
        networks.append(network)
    for value in listeners:
        address = ipaddress.ip_address(value)
        if str(address) != value or address in addresses:
            raise ValueError("noncanonical or repeated SSH listener refused")
        matching = [network for network in networks if address.version == network.version and address in network]
        if not matching:
            raise ValueError("SSH listener does not belong to an admitted source prefix")
        if any((network.version == 4 and network.prefixlen < 31
                and address in (network.network_address, network.broadcast_address))
               or (network.version == 6 and network.prefixlen < 127 and address == network.network_address)
               for network in matching):
            raise ValueError("SSH listener is a subnet boundary address")
        addresses.append(address)
    if any(not any(address.version == network.version and address in network for address in addresses)
           for network in networks):
        raise ValueError("SSH source prefix lacks a corresponding explicit listener")
    return (tuple(sorted(networks, key=lambda value: (value.version, int(value.network_address), value.prefixlen))),
            tuple(sorted(addresses, key=lambda value: (value.version, int(value)))))


def cryptography():
    # Fixed prospective profile, not provider/FIPS/peer or negotiated proof.
    # Use replacement lists: never append to unobserved vendor defaults.
    return {
        "profile": "hybrid-required-aes-gcm-ed25519-rsa-sha2-v1",
        "directives": {
            "KexAlgorithms": "sntrup761x25519-sha512@openssh.com",
            "Ciphers": "aes256-gcm@openssh.com,aes128-gcm@openssh.com",
            "MACs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
            "HostKeyAlgorithms": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
            "PubkeyAcceptedAlgorithms": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
            "CASignatureAlgorithms": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
            "RequiredRSASize": "3072", "FingerprintHash": "sha256", "RekeyLimit": "256M 1h",
        },
        "authority": {name: False for name in (
            "native_provider_usable", "native_azure_policy_proven", "peer_compatibility_proven",
            "transport_algorithms_negotiated", "signature_algorithms_authenticated",
            "fips_compliance_proven", "post_quantum_authentication_proven",
        )},
        "limits": [
            "Hybrid-only KEX requires peer support and has no classical fallback. This is not a FIPS profile or proof of post-quantum authentication: Ed25519 and RSA signatures remain classical.",
            "AES-GCM supplies its own authentication; the separate MACs list does not add another MAC or provide a non-AEAD cipher fallback. Cipher ordering cannot force a client's preference.",
            "RSA SHA-2 signature names are distinct from the ssh-rsa public-key blob type; RequiredRSASize declares a minimum, not key-generation/prime/possession or host-key availability proof.",
            "Rekey data/time limits are declarations, not measured negotiation or physical session deadlines. Algorithm-name listings and offline parser output do not establish provider usability, live handshake/authentication, actual invocation, target cryptographic policy or FIPS compliance.",
        ],
    }


def bundle(prefixes=DEFAULT_PREFIXES, listeners=DEFAULT_LISTEN):
    networks, addresses = sources(prefixes, listeners)
    crypto = cryptography()
    lines = [
        "# Standalone candidate only; use a checked dedicated -f configuration.",
        "Port 22", "AddressFamily any",
        *("ListenAddress " + str(address) for address in addresses),
        "HostKey /etc/azurelinux3s4/ssh/ssh_host_ed25519_key",
        "HostKey /etc/azurelinux3s4/ssh/ssh_host_rsa_key",
        *(name + " " + value for name, value in crypto["directives"].items()),
        "PermitRootLogin no", "PubkeyAuthentication yes", "AuthenticationMethods publickey",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitEmptyPasswords no",
        "HostbasedAuthentication no", "GSSAPIAuthentication no", "UsePAM yes", "StrictModes yes",
        "UseDNS no", "AuthorizedKeysFile /etc/azurelinux3s4/ssh/admin_authorized_keys",
        "RevokedKeys /etc/azurelinux3s4/ssh/admin_revoked_keys",
        "AuthorizedKeysCommand none", "AuthorizedPrincipalsFile none", "AuthorizedPrincipalsCommand none",
        "TrustedUserCAKeys none",
        "AllowUsers " + " ".join(ADMIN + "@" + network.with_prefixlen for network in networks),
        "PermitUserEnvironment no", "PermitUserRC no", "PermitTTY yes",
        "DisableForwarding yes", "AllowTcpForwarding no", "AllowStreamLocalForwarding no",
        "AllowAgentForwarding no", "X11Forwarding no", "PermitTunnel no", "GatewayPorts no",
        "PermitOpen none", "PermitListen none", "Compression no",
        "LoginGraceTime 30", "MaxAuthTries 3", "MaxSessions 2", "MaxStartups 10:30:30",
        "ClientAliveInterval 60", "ClientAliveCountMax 2", "ChannelTimeout session=5m",
        "LogLevel VERBOSE", "Subsystem sftp internal-sftp",
    ]
    content = "\n".join(lines) + "\n"
    data = content.encode("ascii")
    return {
        "scope": "SSH standalone candidate configuration only; default loopback bindings, no installation or login authorization.",
        "admin_account_name": ADMIN,
        "source_prefixes": [network.with_prefixlen for network in networks],
        "listen_addresses": [str(address) for address in addresses],
        "cryptography": crypto,
        "files": [{"file": "ssh/sshd_config", "mode": "0644", "bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(), "content": content}],
        "authority": {name: False for name in (
            "installation_authorized", "accounts_created", "account_identity_admitted", "admin_keys_provisioned",
            "host_keys_provisioned", "key_ownership_verified", "local_network_trusted", "original_client_origin_proven",
            "firewall_enforced", "native_azure_policy_proven", "ssh_authentication_executed", "services_activated",
            "console_recovery_proven", "administrative_privilege_policy_satisfied", "server_ready",
        )},
        "prerequisites": [
            "Authenticated owner/admin credential discovery and conflict-safe dedicated account/key provisioning without operator follow-up; checked account/PAM/shell/group/privilege policy.",
            "Root-owned protected host/private-key and authorized-key paths; vetted supported key material, permissions, rotation and console recovery.",
            "Positive native Azure Linux3 OpenSSH effective-configuration/authentication and cryptographic/PAM-policy checks on SAME bytes, checked dedicated -f invocation, no command-line overrides or borrowed vendor Include/drop-in policy.",
            "For LAN access, independently checked assigned listener addresses/direct interface and source prefixes, firewall and original-client/topology authorization before activation; private address classes alone are not trusted provenance.",
            "Conflict-safe port/service installation, checked persistence/boot/repair and authenticated local/physical administrative access and recovery proof.",
        ],
        "limits": [
            "The CLI emits loopback-only bindings. The internal compiler accepts canonical explicit loopback, RFC1918 or IPv6 ULA prefixes and matching listeners only; no wildcard, public/GUA, link-local/zone, hostname or host-bit inference. Address classes and membership do not prove physical adjacency, interface assignment or original-client identity. NAT/proxies/VPN/tunnels and another local process can obscure origin; topology/firewall/caller/key authorization is separate.",
            "Key-only and source-qualified AllowUsers are configuration declarations, not created accounts, authenticated/provisioned keys or native login/refusal evidence. Root/strict ownership, host-key availability/PAM/console recovery/privilege handling and actual Azure service invocation remain unfinished. No sudo removal or administrative entitlement is inferred.",
            "The file is a standalone candidate, not a vendor drop-in. OpenSSH first-value and additive-list semantics require checked complete effective configuration and invocation. Local parser evidence is not service activation, account/PAM/key/origin enforcement or target version proof. Explicit replacement cryptographic allowlists are prospective; target-specific compiled/vendor cryptographic policy admission remains unfinished. Unsupported providers or peers must defer installation, not silently weaken this profile.",
            "Disabled protocol forwarding does not prevent a permitted shell user from running another forwarder. Channel/session limits and timeouts do not prove process cleanup, complete shell/host/LAN containment or availability. Kernel/root/base/OpenSSH/PAM/private ancestry and finite honest IO/scheduling remain assumptions; all earlier readiness gates persist.",
        ],
    }


def main():
    if len(sys.argv) != 1:
        print("SSH candidate refuses overrides", file=sys.stderr)
        return 64
    resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        result = bundle()
    except (OSError, ValueError, MemoryError) as error:
        print("SSH candidate refused: " + str(error), file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
}

s4_inspect_ssh_keys() {
    # Optional read-only public-key diagnostic, never credential provisioning.
    local seconds=30
    [[ $# == 2 ]] && seconds=150
    timeout --kill-after=5s "${seconds}s" python3 -I - "$@" <<'PY'
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


def snapshot(path, allow_empty=False):
    before = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_mode & 0o022 or not (0 if allow_empty is True else 1) <= before.st_size <= SOURCE_LIMIT):
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


def parse(data, allow_empty=False):
    if (not (0 if allow_empty is True else 1) <= len(data) <= SOURCE_LIMIT
            or data and not data.endswith(b'\n')
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
    if not keys and allow_empty is not True:
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


def native_revocations(keys, revoked):
    """Check known positive/negative controls and complete supplied membership."""
    receipts = []
    with tempfile.TemporaryDirectory(prefix='s4-ssh-revocation-inspection-') as directory:
        base, private = Path(directory), {}

        def remember(path, content=None):
            observed = snapshot(path, allow_empty=True)
            if content is not None and observed != content:
                raise ValueError('private revocation input differs from admitted bytes')
            private[path] = (observed, identity(path.stat(follow_symlinks=False)))
            return observed

        def write(name, content):
            path = base / name
            with path.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
            remember(path, content)
            return path

        def run(label, arguments):
            output, errors = base / (label + '.stdout'), base / (label + '.stderr')
            with output.open('xb') as stdout, errors.open('xb') as stderr:
                os.fchmod(stdout.fileno(), 0o600); os.fchmod(stderr.fileno(), 0o600)
                result = subprocess.run([KEYGEN, *arguments], stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                                        timeout=10, check=False)
            actual, diagnostics = bounded_output(output, 32768), bounded_output(errors, 8192)
            if diagnostics:
                raise ValueError('native revocation diagnostics refused')
            return result.returncode, actual

        def build(label, source):
            path = base / (label + '.krl')
            result, output = run('build-' + label, ['-k', '-q', '-f', str(path), str(source)])
            if result != 0 or output:
                raise ValueError('native KRL construction refused')
            content = remember(path)
            if not content.startswith(b'SSHKRL\n\0'):
                raise ValueError('native KRL header refused')
            return path

        def query(label, krl, paths, states):
            result, output = run('query-' + label, ['-Q', '-f', str(krl), *(str(path) for path in paths)])
            expected = ''.join(str(path) + ' (' + COMMENT + '): ' + ('REVOKED' if state else 'ok') + '\n'
                               for path, state in zip(paths, states)).encode()
            if result != int(any(states)) or output != expected:
                raise ValueError('complete native revocation records do not match supplied membership')
            receipts.append({'control': label, 'keys_compared': len(paths), 'revoked_records': sum(states),
                             'actual_native_exit': result, 'complete_record_sha256': hashlib.sha256(output).hexdigest()})

        candidate_paths = [write('candidate-' + str(index).zfill(3) + '.pub', key['entry'].removeprefix('restrict,pty ').encode())
                           for index, key in enumerate(keys)]
        revoked_paths = [write('revoked-' + str(index).zfill(3) + '.pub', key['entry'].removeprefix('restrict,pty ').encode())
                         for index, key in enumerate(revoked)]
        empty = write('empty.pub', b'')
        positive = write('positive.pub', keys[0]['entry'].removeprefix('restrict,pty ').encode())
        supplied = write('supplied.pub', ''.join(key['entry'].removeprefix('restrict,pty ') for key in revoked).encode())
        query('known-negative', build('empty', empty), candidate_paths[:1], [False])
        query('known-positive', build('positive', positive), candidate_paths[:1], [True])
        revoked_fingerprints = {key['fingerprint'] for key in revoked}
        candidate_states = [key['fingerprint'] in revoked_fingerprints for key in keys]
        query('supplied', build('supplied', supplied), [*candidate_paths, *revoked_paths],
              [*candidate_states, *([True] * len(revoked))])
        for path, (content, observed) in private.items():
            if snapshot(path, allow_empty=True) != content or identity(path.stat(follow_symlinks=False)) != observed:
                raise ValueError('private revocation snapshot changed during native comparison')
        if any(candidate_states):
            raise ValueError('candidate contains a listed revoked public key')
    return receipts


def inspect_policy(path, revoked_path):
    data, revoked_data = snapshot(path), snapshot(revoked_path, allow_empty=True)
    keys, revoked = parse(data), parse(revoked_data, allow_empty=True)
    authorized_content = ''.join(key['entry'] for key in keys).encode()
    revoked_content = ''.join(key['entry'].removeprefix('restrict,pty ') for key in revoked).encode()
    native_fingerprints(authorized_content, keys)
    if revoked:
        native_fingerprints(revoked_content, revoked)
    receipts = native_revocations(keys, revoked)
    return {
        'scope': 'SUPPLIED PUBLIC-KEY / PLAIN REVOCATION SNAPSHOT COMPARISON ONLY',
        'sources': {'candidate_keys': {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
                    'revocations': {'bytes': len(revoked_data), 'sha256': hashlib.sha256(revoked_data).hexdigest()}},
        'candidate_fingerprints': [key['fingerprint'] for key in keys],
        'revoked_fingerprints': [key['fingerprint'] for key in revoked],
        'explicit_empty_revocation_declaration': not revoked,
        'files': [{'file': name, 'mode': '0600', 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(),
                   'content': content.decode()} for name, content in (
                       ('ssh/admin_authorized_keys', authorized_content), ('ssh/admin_revoked_keys', revoked_content))],
        'native_comparison': receipts,
        'attempt_budget': {'native_operations_max': 8, 'native_operation_timeout_seconds': 10,
                           'local_work_cleanup_reserve_seconds': 70, 'outer_timeout_seconds': 150,
                           'outer_kill_grace_seconds': 5},
        'authority': {name: False for name in (
            'administrator_credential_authorized', 'owner_authority_verified', 'revocation_source_authenticated',
            'revocation_policy_complete', 'revocation_freshness_proven', 'private_key_possession_proven',
            'cryptographic_validity_proven', 'root_managed_destination_proven', 'trusted_source_ancestry_proven',
            'native_azure_policy_proven', 'native_sshd_revocation_enforced', 'ssh_authentication_executed',
            'keys_provisioned', 'installation_authorized', 'services_activated', 'server_ready')},
        'limits': [
            'Both inputs are explicit inspecting-user-owned snapshots; no source discovery or default empty substitution. '
            'An empty or comment-only supplied list is an unauthenticated declaration, not current/complete revocation policy.',
            'Only the accepted strong bare Ed25519/RSA public-key profile is supported. Certificates, KRL inputs, '
            'fingerprint-only records, options and unsupported/weak legacy keys defer rather than being silently ignored.',
            'Known revoked/unrevoked native controls and all supplied membership records are checked using private generated '
            'KRLs; those KRLs are not emitted or installed. The prospective deterministic server file is plain public keys.',
            'Comparing supplied lists is not authority, freshness, cryptographic validity or native sshd enforcement. '
            'Future installation must authorize and consume SAME candidate/plain-revocation bytes under checked root-owned '
            'destination and complete effective invocation. Missing/unreadable RevokedKeys must remain fail-closed.',
            'Sequential snapshots are not atomic/ABA/concurrent-root or parent-provenance guarantees. Trusted native '
            'base/OpenSSH/Python/private ancestry and finite honest IO/scheduling remain assumptions; normal cleanup precedes '
            'success, abrupt termination may leave owned PUBLIC-only temporary files. No login/activation/readiness proof.'
        ],
    }


def main():
    if len(sys.argv) not in (2, 3):
        return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (85, 90) if len(sys.argv) == 3 else (20, 25))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = inspect_policy(sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else inspect(sys.argv[1])
    except (OSError, ValueError, subprocess.SubprocessError):
        # Never echo source data: a mistaken private/secret input must not leak.
        print('SSH public-key inspection refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
PY
}

s4_inspect_ssh_account() {
    s4_inspect_ssh_administrator account
}

s4_inspect_ssh_home() {
    s4_inspect_ssh_administrator home
}

s4_inspect_ssh_administrator() {
    [[ $# == 1 && ( $1 == account || $1 == home ) ]] || return 64
    local allowance=30s
    [[ $1 != home ]] || allowance=45s
    timeout --kill-after=5s "$allowance" python3 -I - "$1" <<'PY'
__name__ = 's4_ssh_administrator_library'
"""Observe protected local admin records without NSS lookup or account changes."""

from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
import re
import resource
import stat
import sys


ADMIN = 'azurelinux3s4-admin'
HOME_PATH = '/home/' + ADMIN
SHELL_PATHS = ('/bin/bash', '/usr/bin/bash')
TRUSTED_UID = 0
SOURCE_LIMIT = 1024 * 1024
RECORD_LIMIT = 16384
NAME = re.compile(r'[a-z_][a-z0-9_.-]{0,31}\$?\Z', re.ASCII)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def trusted(value, kind):
    if value.st_uid != TRUSTED_UID or value.st_mode & 0o022 or not kind(value.st_mode):
        raise ValueError('local account source has unsupported type, ownership or permissions')


def root_open():
    return os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)


def read_file(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    pieces, size = [], 0
    while True:
        piece = os.read(descriptor, min(65536, SOURCE_LIMIT + 1 - size))
        if not piece: break
        pieces.append(piece); size += len(piece)
        if size > SOURCE_LIMIT: raise ValueError('local account source exceeds bound')
    return b''.join(pieces)


@contextmanager
def database_snapshot():
    # Literal paths anchored at held protected root/etc descriptors. No NSS or
    # shadow calls, ancestry aliases, source repair or pathname-based mutation.
    with ExitStack() as stack:
        root = root_open(); stack.callback(os.close, root)
        root_identity = identity(os.fstat(root)); trusted(os.fstat(root), stat.S_ISDIR)
        before = os.stat('etc', dir_fd=root, follow_symlinks=False); trusted(before, stat.S_ISDIR)
        directory = os.open('etc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root)
        stack.callback(os.close, directory)
        directory_identity = identity(os.fstat(directory))
        if directory_identity != identity(before): raise ValueError('account source ancestry changed')
        content, observed, descriptors = {}, {}, {}
        for name in ('passwd', 'group', 'shells'):
            before = os.stat(name, dir_fd=directory, follow_symlinks=False); trusted(before, stat.S_ISREG)
            if not 0 < before.st_size <= SOURCE_LIMIT: raise ValueError('empty or excessive local account source')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            stack.callback(os.close, fd)
            if identity(os.fstat(fd)) != identity(before): raise ValueError('local account leaf changed before read')
            data = read_file(fd)
            if len(data) != before.st_size or identity(os.fstat(fd)) != identity(before):
                raise ValueError('local account source changed during read')
            content[name], observed[name], descriptors[name] = data, identity(before), fd
        yield content
        # Require a second whole read of each held regular object and fresh
        # namespace/ancestry observations before releasing the observation.
        for name, fd in descriptors.items():
            if (read_file(fd) != content[name] or identity(os.fstat(fd)) != observed[name]
                    or identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != observed[name]):
                raise ValueError('local account snapshot or namespace changed')
        fresh_root = root_open(); stack.callback(os.close, fresh_root)
        if (identity(os.fstat(root)) != root_identity or identity(os.fstat(fresh_root)) != root_identity
                or identity(os.fstat(directory)) != directory_identity
                or identity(os.stat('etc', dir_fd=fresh_root, follow_symlinks=False)) != directory_identity):
            raise ValueError('local account ancestry changed during observation')
        # ExitStack checks ordinary descriptor closes before caller success.


def lines(data):
    if (not 0 < len(data) <= SOURCE_LIMIT or not data.endswith(b'\n')
            or any(value < 32 and value != 10 or value == 127 for value in data)):
        raise ValueError('unsupported local account source encoding or lines')
    # Local records end at byte LF; Unicode splitlines would invent entries.
    # Account for every raw record, including comments/empties, before decoding.
    raw = data[:-1].split(b'\n')
    if len(raw) > RECORD_LIMIT or any(len(value) > 4096 for value in raw):
        raise ValueError('local account record bounds exceeded')
    values = [value.decode('utf-8') for value in raw]
    if any('\x80' <= character <= '\x9f' or character in '\u2028\u2029'
           for value in values for character in value):
        raise ValueError('unsupported non-LF Unicode separator or control')
    return [value for value in values if value and not value.startswith('#')]


def number(value):
    if not re.fullmatch(r'0|[1-9][0-9]{0,9}', value, flags=re.ASCII) or int(value) > 4294967294:
        raise ValueError('unsupported local numeric identity')
    return int(value)


def records(data, kind):
    values = {}
    for line in lines(data):
        fields = line.split(':')
        if (len(fields) != (7 if kind == 'passwd' else 4) or not NAME.fullmatch(fields[0])
                or fields[0] in values or fields[1] not in ('x', '*', '!', '!!', '')):
            raise ValueError('unsupported, duplicate or credential-bearing local account record')
        if kind == 'passwd':
            values[fields[0]] = {'name': fields[0], 'uid': number(fields[2]), 'gid': number(fields[3]),
                                 'home': fields[5], 'shell': fields[6]}
        else:
            members = fields[3].split(',') if fields[3] else []
            if len(members) != len(set(members)) or any(not NAME.fullmatch(value) for value in members):
                raise ValueError('unsupported or repeated local group membership')
            values[fields[0]] = {'name': fields[0], 'gid': number(fields[2]), 'members': members}
    return values


def classify(content):
    users, groups = records(content['passwd'], 'passwd'), records(content['group'], 'group')
    if (users.get('root', {}).get('uid') != 0 or users['root']['gid'] != 0
            or groups.get('root', {}).get('gid') != 0):
        raise ValueError('local root baseline is missing or unsupported')
    shells = lines(content['shells'])
    if (not shells or len(shells) != len(set(shells)) or any(not value.startswith('/') or value == '/'
            or '//' in value or any(part in ('.', '..') for part in value.split('/'))
            or value.endswith('/') or any(character.isspace() for character in value) for value in shells)):
        raise ValueError('local shell registration is unsupported')
    user, group = users.get(ADMIN), groups.get(ADMIN)
    memberships = [entry['name'] for entry in groups.values() if ADMIN in entry['members']]
    if user is None:
        if group is not None or memberships: raise ValueError('administrator name has local group residue or collision')
        return {'local_status': 'absent', 'account': None, 'local_supplementary_groups': []}
    if (group is None or not 1000 <= user['uid'] <= 60000 or not 1000 <= user['gid'] <= 60000
            or user['gid'] != group['gid'] or user['home'] != HOME_PATH or user['shell'] not in SHELL_PATHS
            or user['shell'] not in shells):
        raise ValueError('existing administrator record does not match the prospective local profile')
    if (sum(entry['uid'] == user['uid'] for entry in users.values()) != 1
            or sum(entry['gid'] == user['gid'] for entry in groups.values()) != 1
            or any(entry['name'] != ADMIN and entry['gid'] == user['gid'] for entry in users.values())
            or set(group['members']) - {ADMIN} or set(memberships) - {ADMIN}):
        raise ValueError('administrator numeric identity or local groups are shared or privileged')
    return {'local_status': 'present', 'account': user, 'local_supplementary_groups': []}


def observe():
    with database_snapshot() as content:
        classification = classify(content)
        sources = {name: {'path': '/etc/' + name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                   for name, data in content.items()}
    return {
        'scope': 'PROTECTED LOCAL ADMINISTRATOR RECORD / GROUP / SHELL-REGISTRATION OBSERVATIONS ONLY',
        'administrator_name': ADMIN, **classification, 'sources': sources,
        'authority': {name: False for name in (
            'existing_identity_authorized', 'nss_resolution_proven', 'uid_gid_reserved', 'account_created',
            'account_adoption_authorized', 'shadow_password_or_expiry_state_admitted', 'pam_policy_admitted',
            'shell_executable_or_loadable_proven', 'home_directory_admitted', 'kernel_groups_admitted',
            'sudo_or_privilege_policy_satisfied', 'credentials_provisioned', 'local_origin_proven',
            'ssh_authentication_executed', 'installation_authorized', 'server_ready')},
        'limits': [
            'Local file records only, not NSS/directory-service existence or effective kernel memberships. '
            'Absence is not permission to allocate UID/GID or create an account; matching presence is not permission '
            'to reuse an identity. Source files are not authentication or owner intent.',
            'The prospective profile uses private same-name primary group, UID/GID1000..60000, fixed home and registered '
            'bash spelling without local supplementary memberships. This is repository policy, not vendor allocator '
            'configuration, shell binary/ACL/LSM/capability/noexec/loadability or home-filesystem admission.',
            'No shadow/gshadow, PAM, NSS, sudoers, credentials or interpreter execution. Password storage fields '
            'and GECOS are not emitted; inline credential-bearing/unsupported records defer. Missing/unsafe/malformed '
            'sources are not converted into absence or repaired.',
            'Held protected no-follow root/etc/regular snapshots, two reads and namespace/metadata observations are '
            'sequential, not atomic/ABA/concurrent-root, content authenticity or physical durability guarantees. '
            'Trusted root/kernel/base/Python/private ancestry and finite honest IO/scheduling remain assumptions. '
            'No account/installation/SSH/PAM/privilege/recovery/target-Azure/ARM/full-server enforcement follows.'
        ],
    }


def main():
    if len(sys.argv) != 1: return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = observe()
    except (OSError, ValueError):
        print('SSH local account observation refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': sys.exit(main())
"""Observe a fixed administrator home and named startup files; never apply it."""

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import resource
import stat
import sys


HOME_ADMIN = 'azurelinux3s4-admin'
HOME_FIXED_PATH = '/home/' + HOME_ADMIN
HOME_OWNER_UID = 0
HOME_OWNER_GID = 0
HOME_FILE_LIMIT = 512 * 1024
HOME_STARTUPS = ('.bash_profile', '.bash_login', '.profile', '.bashrc', '.bash_logout')


def home_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def home_root_open():
    return os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)


def home_trusted(value, kind, modes=None, root_group=False):
    if (not kind(value.st_mode) or value.st_uid != HOME_OWNER_UID or value.st_mode & 0o022
            or root_group and value.st_gid != HOME_OWNER_GID
            or modes is not None and stat.S_IMODE(value.st_mode) not in modes):
        raise ValueError('unsupported administrator home object')


def home_read(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    parts, size = [], 0
    while True:
        value = os.read(descriptor, min(65536, HOME_FILE_LIMIT + 1 - size))
        if not value: return b''.join(parts)
        parts.append(value); size += len(value)
        if size > HOME_FILE_LIMIT: raise ValueError('administrator startup source exceeds bound')


@contextmanager
def home_namespace(local_status):
    with ExitStack() as stack:
        root = home_root_open(); stack.callback(os.close, root)
        root_value = home_identity(os.fstat(root)); home_trusted(os.fstat(root), stat.S_ISDIR)
        directories, files, missing, observations = [], [], [], []

        def directory(parent, name, path, modes=None, root_group=False):
            try: before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                missing.append((parent, name)); observations.append({'path': path, 'kind': 'directory', 'status': 'absent'})
                return None
            home_trusted(before, stat.S_ISDIR, modes, root_group)
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, descriptor)
            if home_identity(os.fstat(descriptor)) != home_identity(before): raise ValueError('home directory changed before admission')
            directories.append((parent, name, descriptor, home_identity(before)))
            observations.append({'path': path, 'kind': 'directory', 'status': 'present',
                                 'uid': before.st_uid, 'gid': before.st_gid, 'mode': f'{stat.S_IMODE(before.st_mode):04o}'})
            return descriptor

        def leaf(parent, name, path):
            try: before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                missing.append((parent, name)); observations.append({'path': path, 'kind': 'startup', 'status': 'absent'})
                return
            home_trusted(before, stat.S_ISREG, (0o444, 0o644), True)
            if before.st_nlink != 1 or before.st_size > HOME_FILE_LIMIT:
                raise ValueError('unsupported linked or excessive startup source')
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, descriptor)
            if home_identity(os.fstat(descriptor)) != home_identity(before): raise ValueError('startup leaf changed before read')
            data = home_read(descriptor)
            if len(data) != before.st_size or home_identity(os.fstat(descriptor)) != home_identity(before):
                raise ValueError('startup source changed during read')
            files.append((parent, name, descriptor, home_identity(before), data))
            observations.append({'path': path, 'kind': 'startup', 'status': 'present', 'bytes': len(data),
                                 'sha256': hashlib.sha256(data).hexdigest(), 'uid': before.st_uid,
                                 'gid': before.st_gid, 'mode': f'{stat.S_IMODE(before.st_mode):04o}'})

        parent = directory(root, 'home', '/home')
        target = directory(parent, HOME_ADMIN, HOME_FIXED_PATH, (0o755,), True) if parent is not None else None
        if target is not None:
            if local_status != 'present': raise ValueError('home exists without matching local account record')
            for name in HOME_STARTUPS: leaf(target, name, HOME_FIXED_PATH + '/' + name)
            ssh = directory(target, '.ssh', HOME_FIXED_PATH + '/.ssh', (0o700, 0o755), True)
            if ssh is not None: leaf(ssh, 'rc', HOME_FIXED_PATH + '/.ssh/rc')
        yield {'home_status': 'present' if target is not None else 'absent', 'objects': observations}
        # Caller repeats account observations while all namespace descriptors
        # remain held. Recheck bytes, identities and absences before closure.
        for parent, name, descriptor, before, data in files:
            if (home_read(descriptor) != data or home_identity(os.fstat(descriptor)) != before
                    or home_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
                raise ValueError('startup snapshot or namespace changed')
        for parent, name, descriptor, before in directories:
            if (home_identity(os.fstat(descriptor)) != before
                    or home_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
                raise ValueError('home directory namespace changed')
        for parent, name in missing:
            try: os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError('absent home object appeared')
        fresh = home_root_open(); stack.callback(os.close, fresh)
        if home_identity(os.fstat(root)) != root_value or home_identity(os.fstat(fresh)) != root_value:
            raise ValueError('home root namespace changed')
        # Checked ExitStack closes precede caller success, including empty data.


def home_account_view(value):
    if (not isinstance(value, dict) or value.get('administrator_name') != HOME_ADMIN
            or value.get('local_status') not in ('absent', 'present')
            or not isinstance(value.get('authority'), dict) or len(value['authority']) != 16
            or any(flag is not False for flag in value['authority'].values())
            or value['local_status'] == 'absent' and value.get('account') is not None
            or value['local_status'] == 'present' and (not isinstance(value.get('account'), dict)
                or value['account'].get('name') != HOME_ADMIN or value['account'].get('home') != HOME_FIXED_PATH)):
        raise ValueError('unsupported local account observation')
    return value


def home_observe(account_observer):
    before = home_account_view(account_observer())
    with home_namespace(before['local_status']) as namespace:
        after = home_account_view(account_observer())
        if before != after: raise ValueError('local account view changed during home observation')
        result = {
            'scope': 'LOCAL HOME AND NAMED STARTUP FILE OBSERVATIONS ONLY', 'administrator_name': HOME_ADMIN,
            'home_path': HOME_FIXED_PATH, 'local_account': before, **namespace,
            'authority': {name: False for name in (
                'account_adoption_authorized', 'home_adoption_authorized', 'creation_or_repair_authorized',
                'startup_contents_authenticated', 'startup_scripts_safe', 'startup_selection_complete',
                'complete_home_inventory', 'user_access_or_acl_policy_proven', 'mount_or_lsm_policy_satisfied',
                'combined_snapshot_atomic', 'nss_or_pam_admitted', 'credential_authority_proven',
                'shell_execution_proven', 'ssh_authentication_executed', 'installation_authorized', 'server_ready')},
            'limits': [
                'Prospective repository profile: home root-owned/root-group0755; optional .ssh root-owned0700/0755; '
                'six named regular startup leaves root-owned/root-group0444/0644, single-linked and bounded. '
                'This is stricter repository policy, not a universal OpenSSH home rule or permission to adopt objects.',
                'Opaque startup bytes are hashed, never emitted, decoded, sourced or executed. No full home inventory, '
                'global shell files, environment/startup selection, ACL/LSM/capability/mount or user-access proof. '
                'A protected existing script is not authenticated or safe to execute.',
                'Two equal qualified local account views bracket held home observations; complete byte/metadata/path '
                'and absence rechecks plus checked closes precede output. Observations remain sequential, '
                'non-atomic/non-ABA/non-concurrent-root, not source authenticity or durability guarantees. '
                'Missing/unsafe/operator objects are neither followed, changed, created nor deleted.',
                'No account/NSS/PAM, credential, locality, privilege, SSH, installation, boot/repair, Azure/ARM or '
                'full-server authority. Trusted root/kernel/base/Python/procfs/private ancestry and finite honest '
                'IO/scheduling remain assumptions; a permitted shell can still execute its own programs.'
            ],
        }
    return result


def home_main(account_observer):
    if len(sys.argv) != 1: return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 35))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = home_observe(account_observer)
    except (OSError, ValueError):
        print('SSH administrator home observation refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True))
    return 0
action = sys.argv[1]
sys.argv = [sys.argv[0]]
raise SystemExit(main() if action == 'account' else home_main(observe))
PY
}

s4_verify_component() {
    case $1 in
        trust-anchor) s4_verify_trust_anchor ;;
        bootstrap) s4_verify_bootstrap ;;
        repository-trust) s4_verify_repository_trust ;;
        update-preparation) s4_update_store verify && s4_timer_state enabled active "$S4_UPDATE_TIMER" ;;
        update-compatibility) s4_check_updates ;;
        update-capacity) s4_check_update_capacity ;;
        update-effects) s4_check_update_effects ;;
        update-interpreters) s4_check_update_interpreters ;;
        update-removals) s4_check_update_removals ;;
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
    [[ $component == trust-anchor || $component == bootstrap || $component == repository-trust || $component == update-preparation || $component == update-compatibility || $component == update-capacity || $component == update-effects || $component == update-interpreters || $component == update-removals ]] || return 78
    if [[ $component == repository-trust || $component == update-preparation || $component == update-compatibility || $component == update-capacity || $component == update-effects || $component == update-interpreters || $component == update-removals ]]; then
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
            update-capacity) s4_check_update_capacity || result=$? ;;
            update-effects) s4_check_update_effects || result=$? ;;
            update-interpreters) s4_check_update_interpreters || result=$? ;;
            update-removals) s4_check_update_removals || result=$? ;;
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
    # Capacity repeats same-byte admission/native TEST, then a 5min+5s observer.
    local capacity=$((compatibility + 305))
    # Effects repeats current admission/TEST and inventories bounded exports
    # within that same native/parent cap; no script is executed by the observer.
    local effects=$compatibility
    # Interpreter files repeat the fresh effects TEST and add a 5min+5s observer.
    local interpreters=$((effects + 305))
    # Removal replacement prerequisites repeat fresh effects TEST, then 90s+5s.
    local removals=$((effects + 95))
    local stages=$((2 * recovery + refresh + download + 3 * store + admission + compatibility + capacity + effects + interpreters + removals))
    # At most 34 state/repository/plugin/timer persistence/control calls on the
    # successful repair branch; reserve 40 to include restoration after failure.
    # Another ten minutes cover trusted local tools, file fsync, cleanup and
    # scheduling outside leaf wrappers. Excessive IO still fails finitely and
    # retains retry ownership; this is not a promise for arbitrary slow storage.
    # Each of compatibility, capacity, effects, interpreters and removals adds four reserves.
    local housekeeping=$((60 * control + 600))
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
            printf 'Usage: sudo ./azurelinux3s4.sh\n       sudo ./azurelinux3s4.sh --status\n       ./azurelinux3s4.sh --web-isolation-policy\n       ./azurelinux3s4.sh --ssh-policy\n       ./azurelinux3s4.sh --inspect-ssh-keys PUBLIC_KEY_FILE\n       ./azurelinux3s4.sh --inspect-ssh-key-policy PUBLIC_KEY_FILE REVOKED_KEY_FILE\n       ./azurelinux3s4.sh --inspect-ssh-account\n       ./azurelinux3s4.sh --inspect-ssh-home\nDevelopment checkpoint: signed-update preparation, read-only RPM tests and candidate web and SSH files. Server hardening and update installation are incomplete.\n'
            return 0 ;;
        --web-isolation-policy)
            [[ $# == 1 ]] || return 64
            s4_web_isolation_policy
            return $? ;;
        --ssh-policy)
            [[ $# == 1 ]] || return 64
            s4_ssh_policy
            return $? ;;
        --inspect-ssh-keys)
            [[ $# == 2 ]] || return 64
            s4_inspect_ssh_keys "$2"
            return $? ;;
        --inspect-ssh-key-policy)
            [[ $# == 3 ]] || return 64
            s4_inspect_ssh_keys "$2" "$3"
            return $? ;;
        --inspect-ssh-account)
            [[ $# == 1 ]] || return 64
            s4_inspect_ssh_account
            return $? ;;
        --inspect-ssh-home)
            [[ $# == 1 ]] || return 64
            s4_inspect_ssh_home
            return $? ;;
        install|--status|--repair|--prepare-updates|--check-updates|--check-update-capacity|--audit-update-effects|--check-update-interpreters|--check-update-removals) [[ $# -le 1 ]] || return 64 ;;
        --verify-rpm) (( $# >= 2 && $# <= 129 )) || return 64 ;;
        --component) [[ $# == 2 && ( $2 == trust-anchor || $2 == bootstrap || $2 == repository-trust || $2 == update-preparation || $2 == update-compatibility || $2 == update-capacity || $2 == update-effects || $2 == update-interpreters || $2 == update-removals ) ]] || return 64 ;;
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
    if [[ $action == --check-update-capacity ]]; then
        s4_verify_trust_anchor || return 75
        s4_check_update_capacity
        return $?
    fi
    if [[ $action == --audit-update-effects ]]; then
        s4_verify_trust_anchor || return 75
        s4_check_update_effects
        return $?
    fi
    if [[ $action == --check-update-interpreters ]]; then
        s4_verify_trust_anchor || return 75
        s4_check_update_interpreters
        return $?
    fi
    if [[ $action == --check-update-removals ]]; then
        s4_verify_trust_anchor || return 75
        s4_check_update_removals
        return $?
    fi
    if [[ $action == --component ]]; then
        case $2 in
            trust-anchor) s4_apply_trust_anchor ;;
            bootstrap) s4_apply_bootstrap ;;
            repository-trust) s4_verify_repository_trust ;;
            update-preparation) s4_prepare_updates ;;
            update-compatibility) s4_check_updates ;;
            update-capacity) s4_check_update_capacity ;;
            update-effects) s4_check_update_effects ;;
            update-interpreters) s4_check_update_interpreters ;;
            update-removals) s4_check_update_removals ;;
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

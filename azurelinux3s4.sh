#!/bin/bash
# Azure Linux 3 Safe SSH Server Set-up. This checkpoint is a bootstrap foundation.
# Full host/network/SSH/web/runtime hardening is deliberately not reported ready.

set -Eeuo pipefail

S4_VERSION=0.4.0
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
S4_COMPONENTS=(trust-anchor bootstrap repository-trust)
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
    for path in "$@"; do
        s4_safe_path "$path" || return 75
    done
    directory=$(mktemp -d "$S4_RUN/package-admission.XXXXXX") || return 75
    trap 'rm -rf -- "$directory"' EXIT
    if timeout --signal=TERM --kill-after=5s 15m python3 -I - \
        "$directory" "$S4_GPG_KEY" "$S4_VENDOR_KEY_SHA256" \
        "$S4_VENDOR_FINGERPRINT" "$@" >"$directory/result.json" <<'PY'
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
    for index, name in enumerate(sys.argv[5:]):
        artifact = root / (str(index) + ".rpm")
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
                      "installs_performed": False, "snapshots_retained": False,
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
    [[ $# == 1 && $1 == makecache ]] || {
        s4_log 'The signed update executor is unfinished; package-changing operations are deferred.'
        return 78
    }
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
        "$S4_VENDOR_FINGERPRINT" "$S4_STATE/tdnf.conf" "$limit" "$@" <<'PY'
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

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
                   "--disableplugin=*", "--enableplugin=tdnfrepogpgcheck", *sys.argv[7:]]
        transaction = run(*command, timeout=240 if sys.argv[6] == "5m" else 800)
        print(transaction.stdout, end="")
        print(transaction.stderr, end="", file=sys.stderr)
        output = transaction.stdout + transaction.stderr
        if transaction.returncode:
            sys.exit(transaction.returncode if 0 < transaction.returncode < 126 else 75)
        if "Loaded plugin: tdnfrepogpgcheck" not in output or "Error loading plugin" in output:
            raise ValueError("native metadata verifier participation was not observed")
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: trusted metadata transaction deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
PY
}

s4_verify_repository_trust() {
    # A stored success marker is insufficient. Re-import the pinned key and
    # require a fresh native signed refresh of both enabled production repos.
    s4_tdnf makecache
}

s4_verify_component() {
    case $1 in
        trust-anchor) s4_verify_trust_anchor ;;
        bootstrap) s4_verify_bootstrap ;;
        repository-trust) s4_verify_repository_trust ;;
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
    [[ $component == trust-anchor || $component == bootstrap || $component == repository-trust ]] || return 78
    if [[ $component == repository-trust ]]; then
        # Its health check IS an online signed refresh. Honor backoff before
        # network work and do not repeat the same failed refresh in a child.
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
        if s4_verify_repository_trust; then
            s4_write_state "$component" complete 0 0 0
            return $?
        else
            result=$?
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

s4_install_units() {
    s4_safe_path "$S4_SYSTEMD_DIR" || return $?
    s4_atomic_write "$S4_SYSTEMD_DIR/azurelinux3s4-repair.service" 0644 <<EOF || return $?
[Unit]
Description=Retry incomplete Azure Linux 3 server setup components
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $S4_INSTALL_DIR/azurelinux3s4.sh --repair
TimeoutStartSec=20min
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
    # OnBootSec makes an offline reboot resume work; no network-online gate stalls
    # timer installation. Failed one-shots remain eligible for the next attempt.
    timeout --kill-after=5s 30s systemctl daemon-reload || return $?
    s4_start_repair_timer
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
    [[ $unit == "$S4_REPAIR_TIMER" || $unit == "$S4_RECOVERY_TIMER" ]] || return 78
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
            printf 'Usage: sudo ./azurelinux3s4.sh\n       sudo ./azurelinux3s4.sh --status\nDevelopment checkpoint: trust anchor, bootstrap and repository trust only; server hardening is incomplete.\n'
            return 0 ;;
        install|--status|--repair) [[ $# -le 1 ]] || return 64 ;;
        --verify-rpm) (( $# >= 2 && $# <= 129 )) || return 64 ;;
        --component) [[ $# == 2 && ( $2 == trust-anchor || $2 == bootstrap || $2 == repository-trust ) ]] || return 64 ;;
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
    if [[ $action == --component ]]; then
        case $2 in
            trust-anchor) s4_apply_trust_anchor ;;
            bootstrap) s4_apply_bootstrap ;;
            repository-trust) s4_verify_repository_trust ;;
        esac
        return $?
    fi
    if [[ $action == install ]]; then
        s4_install_runner || return $?
        s4_install_units || return $?
        s4_repair yes || return $?
        s4_log 'INCOMPLETE: trust anchor, bootstrap and repository trust only. This checkpoint has not hardened the server.'
        return 78
    fi
    s4_repair no
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    s4_main "$@"
fi

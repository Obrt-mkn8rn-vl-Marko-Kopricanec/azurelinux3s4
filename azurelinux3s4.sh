#!/bin/bash
# Azure Linux 3 Safe SSH Server Set-up. This checkpoint is a bootstrap foundation.
# Full host/network/SSH/web/runtime hardening is deliberately not reported ready.

set -Eeuo pipefail

S4_VERSION=0.1.1
S4_OS_RELEASE=/etc/os-release
S4_SYSTEMD_RUNTIME=/run/systemd/system
S4_STATE=/var/lib/azurelinux3s4
S4_RUN=/run/azurelinux3s4
S4_INSTALL_DIR=/usr/local/lib/azurelinux3s4
S4_SYSTEMD_DIR=/etc/systemd/system
S4_GPG_KEY=/etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
S4_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.trust.crt
S4_PLUGIN_CONFIG=/etc/tdnf/pluginconf.d/tdnfrepogpgcheck.conf
S4_PLUGIN_LIBRARY=/usr/lib64/tdnf-plugins/libtdnfrepogpgcheck.so
S4_REPAIR_TIMER=azurelinux3s4-repair.timer
S4_COMPONENTS=(bootstrap)
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
    for tool in awk bash cat chmod cmp date dirname flock install mktemp mv rpm \
                ln readlink rm stat sync systemctl tdnf timeout uname; do
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
        chmod "$mode" "$path"
    else
        if ! sync "$temporary" || ! mv -fT -- "$temporary" "$path"; then
            rm -f -- "$temporary"
            return 1
        fi
        sync "$(dirname -- "$path")"
    fi
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

s4_tdnf() {
    s4_verify_metadata || return 75
    timeout --signal=TERM --kill-after=30s 15m \
        tdnf -c "$S4_STATE/tdnf.conf" --releasever=3.0 --refresh -y \
        --disableplugin='*' --enableplugin=tdnfrepogpgcheck "$@" </dev/null
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
    [[ $component == bootstrap ]] || return 78
    if s4_verify_bootstrap; then
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
        if s4_verify_bootstrap; then
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
    # OnBootSec makes an offline reboot resume work; no network-online gate stalls
    # timer installation. Failed one-shots remain eligible for the next attempt.
    timeout --kill-after=5s 30s systemctl daemon-reload || return $?
    s4_start_repair_timer
}

s4_timer_state() {
    local enabled=$1 active=$2 observed
    observed=$(timeout --kill-after=5s 30s systemctl show --no-pager \
        --property=LoadState,UnitFileState,ActiveState "$S4_REPAIR_TIMER") || return 1
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
    local directory=$S4_SYSTEMD_DIR/timers.target.wants link target
    target=$S4_SYSTEMD_DIR/$S4_REPAIR_TIMER
    link=$directory/$S4_REPAIR_TIMER
    s4_safe_path "$target" || return $?
    [[ -f $target ]] || return 78
    s4_directory "$directory" 0755 || return $?
    if [[ -L $link ]]; then
        [[ $(readlink -f -- "$link") == "$target" ]] || return 78
    else
        [[ ! -e $link ]] || return 78
        ln -s -- "$target" "$link" || return $?
        sync "$directory" || return $?
    fi
    [[ -L $link && $(readlink -f -- "$link") == "$target" ]]
}

s4_start_repair_timer() {
    # Retain a checked boot activation link even when the manager is unavailable
    # or a failed disable operation removed the previous link before failing.
    s4_preserve_retry_link || return $?
    timeout --kill-after=5s 30s systemctl enable --now "$S4_REPAIR_TIMER" || return $?
    s4_preserve_retry_link || return $?
    s4_timer_state enabled active
}

s4_finish_repair() {
    local result=0
    if ! printf 'status=pending\n' | s4_atomic_write "$S4_STATE/finalization" 0600; then
        s4_restore_repair_timer
        return 75
    fi
    if timeout --kill-after=5s 30s systemctl disable --now "$S4_REPAIR_TIMER"; then
        if s4_timer_state disabled inactive; then
            if printf 'status=complete\n' | s4_atomic_write "$S4_STATE/finalization" 0600; then
                s4_log 'Bootstrap verified; its repair timer has stopped.'
                return 0
            fi
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
    if ! s4_start_repair_timer; then
        if s4_preserve_retry_link; then
            s4_log 'Boot retry activation is verified; runtime activation could not be verified.'
        else
            s4_log 'Automatic retry activation could not be preserved.'
        fi
    fi
}

s4_repair() {
    local force=$1 component pending=no result attempts
    S4_NOW=$(date +%s)
    if s4_repositories; then
        for component in "${S4_COMPONENTS[@]}"; do
            if ! s4_reconcile_component "$component" "$force"; then
                pending=yes
            fi
        done
    else
        result=$?
        pending=yes
        for component in "${S4_COMPONENTS[@]}"; do
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
    printf 'version=%s\nserver_ready=no\nimplemented_components=bootstrap\n' "$S4_VERSION"
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
            printf 'Usage: sudo ./azurelinux3s4.sh\n       sudo ./azurelinux3s4.sh --status\nDevelopment checkpoint: bootstrap only; server hardening is incomplete.\n'
            return 0 ;;
        install|--status|--repair) [[ $# -le 1 ]] || return 64 ;;
        --component) [[ $# == 2 && $2 == bootstrap ]] || return 64 ;;
        *) s4_log 'Unknown argument. Use --help.'; return 64 ;;
    esac
    s4_preflight || return $?
    if [[ $action == --status ]]; then
        s4_status
        return 0
    fi
    s4_prepare_state || return $?
    s4_lock || return $?
    if [[ $action == --component ]]; then
        s4_apply_bootstrap
        return $?
    fi
    if [[ $action == install ]]; then
        s4_install_runner || return $?
        s4_install_units || return $?
        s4_repair yes || return $?
        s4_log 'INCOMPLETE: bootstrap only. This checkpoint has not hardened the server.'
        return 78
    fi
    s4_repair no
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    s4_main "$@"
fi

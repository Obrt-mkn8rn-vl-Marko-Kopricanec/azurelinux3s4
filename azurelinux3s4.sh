#!/bin/bash
# Azure Linux 3 Safe SSH Server Set-up. This checkpoint is a bootstrap foundation.
# Full host/network/SSH/web/runtime hardening is deliberately not reported ready.

set -Eeuo pipefail

S4_VERSION=0.1.0
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
S4_COMPONENTS=(bootstrap)
S4_BOOTSTRAP_PACKAGES=(ca-certificates curl openssl python3 tdnf-plugin-repogpgcheck)
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
                readlink rm stat sync systemctl tdnf timeout uname; do
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

s4_lock() {
    s4_safe_path "$S4_RUN/operation.lock" || return $?
    # The component child inherits descriptor 9 and the same open-file lock.
    # A separately invoked component must acquire the lock itself.
    if [[ ! -e /proc/$$/fd/9 ]] || \
        [[ $(readlink /proc/$$/fd/9) != "$S4_RUN/operation.lock" ]]; then
        exec 9>"$S4_RUN/operation.lock" || return $?
    fi
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
EOF
}

s4_tdnf() {
    timeout --signal=TERM --kill-after=30s 15m \
        tdnf -c "$S4_STATE/tdnf.conf" --releasever=3.0 --refresh -y "$@" </dev/null
}

s4_verify_bootstrap() {
    local package
    for package in "${S4_BOOTSTRAP_PACKAGES[@]}"; do
        rpm -q "$package" >/dev/null 2>&1 || return 1
    done
    command -v curl >/dev/null || return 1
    command -v python3 >/dev/null || return 1
    command -v update-ca-trust >/dev/null || return 1
    [[ -s $S4_CA_BUNDLE && -f $S4_PLUGIN_LIBRARY && -f $S4_PLUGIN_CONFIG ]] || return 1
    cmp -s -- "$S4_PLUGIN_CONFIG" <(printf '[main]\nenabled=1\n') || return 1
    openssl x509 -in "$S4_CA_BUNDLE" -noout >/dev/null 2>&1
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
    s4_repositories || return $?
    # Rebuild already-installed trust assets before HTTPS operations. A broken
    # RPM post-install hook must not be mistaken for a functional CA bundle.
    if command -v update-ca-trust >/dev/null; then
        update-ca-trust extract || return $?
    fi
    if [[ -f $S4_PLUGIN_LIBRARY ]]; then
        s4_activate_verifier || return $?
    fi
    if ! s4_verify_bootstrap; then
        s4_tdnf install "${S4_BOOTSTRAP_PACKAGES[@]}" || return $?
    fi
    s4_activate_verifier || return $?
    update-ca-trust extract
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
    systemctl daemon-reload || return $?
    systemctl enable --now azurelinux3s4-repair.timer || return $?
    systemctl is-enabled --quiet azurelinux3s4-repair.timer || return $?
    systemctl is-active --quiet azurelinux3s4-repair.timer
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
        systemctl enable --now azurelinux3s4-repair.timer || return 75
        s4_log 'Setup components remain pending; automatic repair will continue.'
        return 75
    fi
    systemctl disable --now azurelinux3s4-repair.timer || return 75
    if systemctl is-enabled --quiet azurelinux3s4-repair.timer || \
        systemctl is-active --quiet azurelinux3s4-repair.timer; then
        s4_log 'Bootstrap is verified, but the repair timer did not stop.'
        return 75
    fi
    s4_log 'Bootstrap verified; its repair timer has stopped.'
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

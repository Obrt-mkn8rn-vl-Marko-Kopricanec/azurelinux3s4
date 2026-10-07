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

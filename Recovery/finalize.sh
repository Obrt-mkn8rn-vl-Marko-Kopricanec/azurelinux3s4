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

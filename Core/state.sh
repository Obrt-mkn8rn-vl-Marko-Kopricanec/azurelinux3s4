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

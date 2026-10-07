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
    [[ $component == trust-anchor || $component == bootstrap || $component == repository-trust || $component == update-preparation || $component == update-compatibility || $component == update-capacity || $component == update-effects || $component == update-interpreters ]] || return 78
    if [[ $component == repository-trust || $component == update-preparation || $component == update-compatibility || $component == update-capacity || $component == update-effects || $component == update-interpreters ]]; then
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

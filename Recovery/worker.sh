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

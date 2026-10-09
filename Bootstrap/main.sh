s4_main() {
    # Ignore caller-supplied tool paths and language/runtime startup configuration.
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    unset BASH_ENV ENV CDPATH PYTHONPATH
    umask 077
    local action=${1:-install}
    case $action in
        --help)
            printf 'Usage: sudo ./azurelinux3s4.sh\n       sudo ./azurelinux3s4.sh --status\n       ./azurelinux3s4.sh --web-isolation-policy\n       ./azurelinux3s4.sh --ssh-policy\n       ./azurelinux3s4.sh --ssh-service-policy\n       sudo ./azurelinux3s4.sh --deployment-policy ROOT_MANIFEST_JSON\n       ./azurelinux3s4.sh --inspect-ssh-keys PUBLIC_KEY_FILE\n       ./azurelinux3s4.sh --inspect-ssh-key-policy PUBLIC_KEY_FILE REVOKED_KEY_FILE\n       ./azurelinux3s4.sh --inspect-ssh-account\n       ./azurelinux3s4.sh --inspect-ssh-home\nDevelopment checkpoint: signed-update preparation, read-only RPM tests and candidate web and SSH files. Server hardening and update installation are incomplete.\n'
            return 0 ;;
        --web-isolation-policy)
            [[ $# == 1 ]] || return 64
            s4_web_isolation_policy
            return $? ;;
        --deployment-policy)
            [[ $# == 2 ]] || return 64
            s4_deployment_policy "$2"
            return $? ;;
        --ssh-policy)
            [[ $# == 1 ]] || return 64
            s4_ssh_policy
            return $? ;;
        --ssh-service-policy)
            [[ $# == 1 ]] || return 64
            s4_ssh_service_policy
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

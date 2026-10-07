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

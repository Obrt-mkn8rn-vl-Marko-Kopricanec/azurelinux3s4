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

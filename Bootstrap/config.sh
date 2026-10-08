#!/bin/bash
# Azure Linux 3 Safe SSH Server Set-up. This checkpoint is a bootstrap foundation.
# Full host/network/SSH/web/runtime hardening is deliberately not reported ready.

set -Eeuo pipefail

S4_VERSION=0.29.0
S4_OS_RELEASE=/etc/os-release
S4_SYSTEMD_RUNTIME=/run/systemd/system
S4_STATE=/var/lib/azurelinux3s4
S4_RUN=/run/azurelinux3s4
S4_INSTALL_DIR=/usr/local/lib/azurelinux3s4
S4_SYSTEMD_DIR=/etc/systemd/system
S4_GPG_KEY=$S4_STATE/vendor-rpm-key.asc
# Azure Linux 3's vendor source key, independently checked against signed
# production base/extended metadata. Rotation requires newly vetted pins.
S4_VENDOR_KEY_SHA256=1092f37ec429e58bf9c7f898df17c3c32eb2ce3c4c037afb8ffe2d2b42e16e89
S4_VENDOR_FINGERPRINT=2BC94FFF7015A5F28F1537AD0CD9FED33135CE90
S4_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.trust.crt
S4_PLUGIN_CONFIG=/etc/tdnf/pluginconf.d/tdnfrepogpgcheck.conf
S4_PLUGIN_LIBRARY=/usr/lib64/tdnf-plugins/libtdnfrepogpgcheck.so
S4_REPAIR_TIMER=azurelinux3s4-repair.timer
S4_RECOVERY_TIMER=azurelinux3s4-finalization-recovery.timer
S4_COMPONENTS=(trust-anchor bootstrap repository-trust update-preparation update-compatibility update-capacity update-effects update-interpreters update-removals)
S4_UPDATE_TIMER=azurelinux3s4-update-preparation.timer
# Internal dynamic-scope options; never accept inherited environment values.
S4_ADMISSION_DESTINATION=
S4_DOWNLOAD_DIRECTORY=
S4_CAPACITY_MODE=
S4_EFFECTS_MODE=
S4_INTERPRETERS_MODE=
S4_REMOVALS_MODE=
S4_BOOTSTRAP_PACKAGES=(ca-certificates curl openssl python3 gnupg2 tdnf-plugin-repogpgcheck)
S4_ARCH=
S4_NOW=

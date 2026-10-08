"""Compile a dedicated SSH service candidate; never invoke or install it."""

import hashlib
import json
import resource
import sys


SERVICE_NAME = 'azurelinux3s4-sshd.service'
SERVICE_CONFIG = '/etc/azurelinux3s4/ssh/sshd_config'
SERVICE_DAEMON = '/usr/sbin/sshd'
SERVICE_CHECK_ARGV = (SERVICE_DAEMON, '-t', '-f', SERVICE_CONFIG)
SERVICE_DAEMON_ARGV = (SERVICE_DAEMON, '-D', '-e', '-f', SERVICE_CONFIG)
SERVICE_CONFIG_LIMIT = 32 * 1024


def service_configuration(policy):
    # Internal producer contract, not an external JSON admission protocol or
    # authority to reuse an arbitrary supplied configuration.
    if (not isinstance(policy, dict) or policy.get('admin_account_name') != 'azurelinux3s4-admin'
            or policy.get('source_prefixes') != ['127.0.0.1/32', '::1/128']
            or policy.get('listen_addresses') != ['127.0.0.1', '::1']
            or not isinstance(policy.get('authority'), dict) or len(policy['authority']) != 15
            or any(value is not False for value in policy['authority'].values())
            or not isinstance(policy.get('files'), list) or len(policy['files']) != 1):
        raise ValueError('unsupported internal SSH candidate')
    entry = policy['files'][0]
    if (not isinstance(entry, dict) or entry.get('file') != 'ssh/sshd_config'
            or entry.get('mode') != '0644' or not isinstance(entry.get('content'), str)):
        raise ValueError('unsupported internal SSH configuration file')
    data = entry['content'].encode('ascii')
    if (not 0 < len(data) <= SERVICE_CONFIG_LIMIT or not data.endswith(b'\n')
            or any(value < 32 and value != 10 or value == 127 for value in data)
            or type(entry.get('bytes')) is not int or entry['bytes'] != len(data)
            or entry.get('sha256') != hashlib.sha256(data).hexdigest()):
        raise ValueError('internal SSH configuration bytes differ')
    return dict(entry)


def service_bundle(policy_producer):
    policy = policy_producer()
    config = service_configuration(policy)
    content = '\n'.join((
        '[Unit]',
        'Description=Azure Linux 3 dedicated SSH administrator candidate',
        'After=network.target',
        'StartLimitIntervalSec=0',
        '',
        '[Service]',
        'Type=exec',
        'User=root',
        'Group=root',
        'ExecStartPre=' + ' '.join(SERVICE_CHECK_ARGV),
        'ExecStart=' + ' '.join(SERVICE_DAEMON_ARGV),
        'Restart=always',
        'RestartSec=30s',
        'TimeoutStartSec=60s',
        'TimeoutStopSec=30s',
        'KillMode=control-group',
        'UMask=0077',
        'LimitCORE=0',
        'NoNewPrivileges=yes',
        'Environment=LC_ALL=C',
        'StandardInput=null',
        'StandardOutput=journal',
        'StandardError=journal',
        '',
        '[Install]',
        'WantedBy=multi-user.target',
        '',
    ))
    data = content.encode('ascii')
    return {
        'scope': 'DEDICATED SSH SERVICE CANDIDATE BYTES ONLY; NO DAEMON OR MANAGER INVOCATION',
        'service_name': SERVICE_NAME, 'configuration_path': SERVICE_CONFIG,
        'configuration_sha256': config['sha256'],
        'check_argv': list(SERVICE_CHECK_ARGV), 'daemon_argv': list(SERVICE_DAEMON_ARGV),
        'ssh_policy': policy,
        'files': [config, {'file': SERVICE_NAME, 'mode': '0644', 'bytes': len(data),
                           'sha256': hashlib.sha256(data).hexdigest(), 'content': content}],
        'authority': {name: False for name in (
            'installation_authorized', 'complete_effective_invocation_admitted', 'native_azure_policy_proven',
            'daemon_executed', 'services_activated', 'boot_enablement_persisted', 'automatic_recovery_proven',
            'configuration_continuity_proven', 'caller_environment_admitted', 'native_runtime_authenticated',
            'account_or_credentials_provisioned', 'pam_or_lsm_compatibility_proven', 'no_new_privileges_enforced',
            'administrative_privilege_policy_satisfied', 'session_cleanup_proven', 'console_recovery_proven',
            'original_client_locality_proven', 'server_ready')},
        'prerequisites': [
            'Authorize and consume the SAME configuration/service bytes at protected root-owned destinations; '
            'admit the entire effective unit, drop-ins, environment, invocation and native runtime. '
            'No alternate command-line configuration or borrowed vendor policy may weaken the candidate.',
            'Positive target OpenSSH/PAM/LSM, host-key, account/key/privilege and authentication checks, '
            'including NoNewPrivileges compatibility and controlled remote-admin/physical recovery policy.',
            'Conflict-safe port/vendor-service/privilege-separation-directory handling and durable '
            'installation, enablement, boot, repair, native startup/retry and session-cleanup evidence.',
            'Independently authorized assigned LAN listeners/topology/firewall/original origin before '
            'extending loopback-only access; private address classes are not original-client identity.',
        ],
        'limits': [
            'The fixed -t precheck and foreground -D -e daemon both name the same dedicated -f path. '
            'Precheck and subsequent pathname opens are sequential: this does not bind runtime opens to '
            'the emitted bytes, prevent races/ABA/root changes or establish full effective invocation.',
            'Type=exec observes exec success, not listening, authentication or health. Startup60s/stop30s '
            'and retry30s are prospective systemd policy; finite software bounds assume honest finite IO '
            'and scheduling. Restart=always includes clean daemon exit and failed prechecks but explicit '
            'manager stop does not restart; disabling start-rate limits is not repair/boot enablement.',
            'NoNewPrivileges, when actually applied, is inherited and prevents privilege growth through '
            'exec setid/file capabilities. It does not remove the root daemon existing privileges, deny '
            'all privileged IPC or establish PAM/LSM/sudo/admin compatibility. No sudo package removal '
            'or physical-console privilege change is performed or authorized.',
            'KillMode=control-group declares termination of daemon/session processes on stop/restart; '
            'no actual manager/cgroup/session cleanup, resource capacity, privilege-separation directory '
            'or authentication evidence follows. No reload command or health/completion gate is supplied.',
            'Standalone candidate emission only; no host/unit/account/key/service installation or activation, '
            'native Azure/ARM/FIPS/PID1/PAM/login/disk/power-loss proof. All accepted SSH/Web/update limits '
            'and trusted root/base/native/private ancestry/finite IO assumptions remain.',
        ],
    }


def service_main(policy_producer):
    if len(sys.argv) != 1: return 64
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = service_bundle(policy_producer)
    except (OSError, ValueError, TypeError, MemoryError):
        print('SSH service candidate refused', file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0

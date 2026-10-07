"""Compile standalone SSH candidate bytes; no account, key or service changes."""

import hashlib
import ipaddress
import json
import resource
import sys


ADMIN = "azurelinux3s4-admin"
DEFAULT_PREFIXES = ("127.0.0.1/32", "::1/128")
DEFAULT_LISTEN = ("127.0.0.1", "::1")
LOCAL_BOUNDS = tuple(ipaddress.ip_network(value) for value in (
    "127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def sources(prefixes, listeners):
    for values in (prefixes, listeners):
        if (not isinstance(values, (tuple, list)) or not 1 <= len(values) <= 64
                or any(not isinstance(value, str) or not value.isascii() or not value or len(value) > 64
                       or "%" in value or any(ord(character) < 33 or ord(character) > 126 for character in value)
                       for value in values)):
            raise ValueError("bounded explicit SSH prefixes and listeners are required")
    networks, addresses = [], []
    for value in prefixes:
        network = ipaddress.ip_network(value, strict=True)
        if (network.with_prefixlen != value or not any(network.version == bound.version and network.subnet_of(bound)
                                                     for bound in LOCAL_BOUNDS)):
            raise ValueError("SSH source prefix is not canonical loopback/private space")
        if any(network.version == previous.version and network.overlaps(previous) for previous in networks):
            raise ValueError("overlapping or repeated SSH source prefixes refused")
        networks.append(network)
    for value in listeners:
        address = ipaddress.ip_address(value)
        if str(address) != value or address in addresses:
            raise ValueError("noncanonical or repeated SSH listener refused")
        matching = [network for network in networks if address.version == network.version and address in network]
        if not matching:
            raise ValueError("SSH listener does not belong to an admitted source prefix")
        if any((network.version == 4 and network.prefixlen < 31
                and address in (network.network_address, network.broadcast_address))
               or (network.version == 6 and network.prefixlen < 127 and address == network.network_address)
               for network in matching):
            raise ValueError("SSH listener is a subnet boundary address")
        addresses.append(address)
    if any(not any(address.version == network.version and address in network for address in addresses)
           for network in networks):
        raise ValueError("SSH source prefix lacks a corresponding explicit listener")
    return (tuple(sorted(networks, key=lambda value: (value.version, int(value.network_address), value.prefixlen))),
            tuple(sorted(addresses, key=lambda value: (value.version, int(value)))))


def bundle(prefixes=DEFAULT_PREFIXES, listeners=DEFAULT_LISTEN):
    networks, addresses = sources(prefixes, listeners)
    lines = [
        "# Standalone candidate only; use a checked dedicated -f configuration.",
        "Port 22", "AddressFamily any",
        *("ListenAddress " + str(address) for address in addresses),
        "HostKey /etc/azurelinux3s4/ssh/ssh_host_ed25519_key",
        "HostKey /etc/azurelinux3s4/ssh/ssh_host_rsa_key",
        "PermitRootLogin no", "PubkeyAuthentication yes", "AuthenticationMethods publickey",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitEmptyPasswords no",
        "HostbasedAuthentication no", "GSSAPIAuthentication no", "UsePAM yes", "StrictModes yes",
        "UseDNS no", "AuthorizedKeysFile /etc/azurelinux3s4/ssh/admin_authorized_keys",
        "AuthorizedKeysCommand none", "AuthorizedPrincipalsFile none", "AuthorizedPrincipalsCommand none",
        "TrustedUserCAKeys none",
        "AllowUsers " + " ".join(ADMIN + "@" + network.with_prefixlen for network in networks),
        "PermitUserEnvironment no", "PermitUserRC no", "PermitTTY yes",
        "DisableForwarding yes", "AllowTcpForwarding no", "AllowStreamLocalForwarding no",
        "AllowAgentForwarding no", "X11Forwarding no", "PermitTunnel no", "GatewayPorts no",
        "PermitOpen none", "PermitListen none", "Compression no",
        "LoginGraceTime 30", "MaxAuthTries 3", "MaxSessions 2", "MaxStartups 10:30:30",
        "ClientAliveInterval 60", "ClientAliveCountMax 2", "ChannelTimeout session=5m",
        "LogLevel VERBOSE", "Subsystem sftp internal-sftp",
    ]
    content = "\n".join(lines) + "\n"
    data = content.encode("ascii")
    return {
        "scope": "SSH standalone candidate configuration only; default loopback bindings, no installation or login authorization.",
        "admin_account_name": ADMIN,
        "source_prefixes": [network.with_prefixlen for network in networks],
        "listen_addresses": [str(address) for address in addresses],
        "files": [{"file": "ssh/sshd_config", "mode": "0644", "bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(), "content": content}],
        "authority": {name: False for name in (
            "installation_authorized", "accounts_created", "account_identity_admitted", "admin_keys_provisioned",
            "host_keys_provisioned", "key_ownership_verified", "local_network_trusted", "original_client_origin_proven",
            "firewall_enforced", "native_azure_policy_proven", "ssh_authentication_executed", "services_activated",
            "console_recovery_proven", "administrative_privilege_policy_satisfied", "server_ready",
        )},
        "prerequisites": [
            "Authenticated owner/admin credential discovery and conflict-safe dedicated account/key provisioning without operator follow-up; checked account/PAM/shell/group/privilege policy.",
            "Root-owned protected host/private-key and authorized-key paths; vetted supported key material, permissions, rotation and console recovery.",
            "Positive native Azure Linux3 OpenSSH effective-configuration/authentication and cryptographic/PAM-policy checks on SAME bytes, checked dedicated -f invocation, no command-line overrides or borrowed vendor Include/drop-in policy.",
            "For LAN access, independently checked assigned listener addresses/direct interface and source prefixes, firewall and original-client/topology authorization before activation; private address classes alone are not trusted provenance.",
            "Conflict-safe port/service installation, checked persistence/boot/repair and authenticated local/physical administrative access and recovery proof.",
        ],
        "limits": [
            "The CLI emits loopback-only bindings. The internal compiler accepts canonical explicit loopback, RFC1918 or IPv6 ULA prefixes and matching listeners only; no wildcard, public/GUA, link-local/zone, hostname or host-bit inference. Address classes and membership do not prove physical adjacency, interface assignment or original-client identity. NAT/proxies/VPN/tunnels and another local process can obscure origin; topology/firewall/caller/key authorization is separate.",
            "Key-only and source-qualified AllowUsers are configuration declarations, not created accounts, authenticated/provisioned keys or native login/refusal evidence. Root/strict ownership, host-key availability/PAM/console recovery/privilege handling and actual Azure service invocation remain unfinished. No sudo removal or administrative entitlement is inferred.",
            "The file is a standalone candidate, not a vendor drop-in. OpenSSH first-value and additive-list semantics require checked complete effective configuration and invocation. Local parser evidence is not service activation, account/PAM/key/origin enforcement or target version proof. No cryptographic algorithm allowlist is emitted; target-specific compiled/vendor cryptographic policy admission remains unfinished.",
            "Disabled protocol forwarding does not prevent a permitted shell user from running another forwarder. Channel/session limits and timeouts do not prove process cleanup, complete shell/host/LAN containment or availability. Kernel/root/base/OpenSSH/PAM/private ancestry and finite honest IO/scheduling remain assumptions; all earlier readiness gates persist.",
        ],
    }


def main():
    if len(sys.argv) != 1:
        print("SSH candidate refuses overrides", file=sys.stderr)
        return 64
    resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        result = bundle()
    except (OSError, ValueError, MemoryError) as error:
        print("SSH candidate refused: " + str(error), file=sys.stderr)
        return 75
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

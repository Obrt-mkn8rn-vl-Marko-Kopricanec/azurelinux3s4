"""Compile explicit R630 network and four-application candidate contracts."""

import hashlib as dep_policy_hash
import ipaddress as dep_ip
import json as dep_policy_json
import re as dep_policy_re
import resource as dep_resource
import sys as dep_sys


# Protocol address classes only, never deployment allocations or defaults.
DEP_PRIVATE4 = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
DEP_APPS = ('mk8.sava', 'mk8.drava', 'mk8.dns', 'mk8.email')
DEP_PORT_NAMES = ('sava_gateway', 'sava_application', 'email_http', 'email_admin', 'dns_health')
DEP_AUTHORITY = (
    'owner_intent_authenticated', 'configuration_installed', 'interface_identity_observed',
    'vlan_parent_identity_observed', 'addresses_assigned', 'ipv6_prefix_assigned_or_routed',
    'original_client_locality_proven', 'nat_proxy_vpn_origin_admitted', 'firewall_enforced',
    'complete_existing_hooks_admitted', 'ssh_keys_accounts_privilege_provisioned',
    'ssh_login_and_public_refusal_proven', 'application_releases_authenticated',
    'application_configuration_bytes_admitted', 'application_runtime_usable',
    'application_service_units_installed', 'application_health_proven', 'public_tls_usable',
    'dns_delegation_and_dnssec_proven', 'mail_delivery_and_relay_refusal_proven',
    'postgresql_provisioned', 'backup_restore_proven', 'durable_reboot_recovery_proven', 'server_ready',
)


def deployment_fields(value, keys):
    if type(value) is not dict or value.keys() != set(keys):
        raise ValueError('exact manifest fields required')


def deployment_text(value, pattern, maximum):
    if type(value) is not str or len(value) > maximum or not dep_policy_re.fullmatch(pattern, value):
        raise ValueError('noncanonical manifest text')
    return value


def deployment_address(value, version):
    if (type(value) is not str or len(value) > 64
            or not dep_policy_re.fullmatch(r'[0-9a-f:.]+', value)):
        raise ValueError('explicit literal address required')
    address = dep_ip.ip_address(value)
    if (address.version != version or str(address) != value or address.is_unspecified
            or address.is_loopback or address.is_link_local or address.is_multicast
            or (version == 6 and (address.scope_id is not None or address.ipv4_mapped is not None))):
        raise ValueError('unsupported server address')
    return address


def deployment_admin(value, version):
    deployment_fields(value, ('interface', 'prefix', 'address', 'routers'))
    interface = deployment_text(value['interface'], r'[A-Za-z][A-Za-z0-9_.-]{0,14}', 15)
    if interface == 'lo':
        raise ValueError('admin interface cannot be loopback')
    prefix = value['prefix']
    if (type(prefix) is not str or not 3 <= len(prefix) <= 64
            or not dep_policy_re.fullmatch(r'[0-9a-f:./]+', prefix)):
        raise ValueError('explicit canonical admin prefix required')
    network = dep_ip.ip_network(prefix, strict=True)
    bounds = DEP_PRIVATE4 if version == 4 else ('fd00::/8',)
    if (network.version != version or network.with_prefixlen != prefix
            or not (24 <= network.prefixlen <= 30 if version == 4 else 64 <= network.prefixlen <= 126)
            or not any(network.subnet_of(dep_ip.ip_network(bound)) for bound in bounds)):
        raise ValueError('bounded private admin prefix required')
    address = deployment_address(value['address'], version)
    if address not in network or address in (network.network_address, network.broadcast_address):
        raise ValueError('admin listener outside exact declared prefix')
    if type(value['routers']) is not list or not 1 <= len(value['routers']) <= 4:
        raise ValueError('explicit bounded admin router exclusions required')
    routers = [deployment_address(item, version) for item in value['routers']]
    if (len(set(routers)) != len(routers) or any(item not in network or item == address
            or item in (network.network_address, network.broadcast_address) for item in routers)):
        raise ValueError('invalid admin router exclusions')
    return {'interface': interface, 'address': str(address), 'prefix': prefix,
            'routers': [str(item) for item in sorted(routers)]}


def deployment_domain(value):
    deployment_text(value, r'[a-z0-9.-]+', 253)
    labels = value.split('.')
    if len(labels) < 2 or any(not dep_policy_re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise ValueError('explicit lowercase DNS name required')
    return value


def deployment_manifest(value):
    deployment_fields(value, ('schema', 'hardware', 'architecture', 'os', 'admin', 'public',
                              'domains', 'dns_zone', 'dns_nodes', 'releases', 'private_ports', 'mail'))
    if (type(value['schema']) is not int or value['schema'] != 1 or value['hardware'] != 'Dell R630'
            or value['architecture'] != 'x86_64' or value['os'] != 'Azure Linux 3'):
        raise ValueError('unsupported deployment target profile')
    deployment_fields(value['admin'], ('ipv4', 'ipv6'))
    admin = [deployment_admin(value['admin']['ipv4'], 4)]
    if value['admin']['ipv6'] is not None:
        admin.append(deployment_admin(value['admin']['ipv6'], 6))
    admin_networks = [dep_ip.ip_network(row['prefix']) for row in admin]
    deployment_fields(value['public'], ('interface', 'topology', 'ipv4', 'ipv6'))
    public_interface = deployment_text(value['public']['interface'], r'[A-Za-z][A-Za-z0-9_.-]{0,14}', 15)
    if public_interface == 'lo' or public_interface in {item['interface'] for item in admin}:
        raise ValueError('separate explicit public and admin interfaces required')
    if value['public']['topology'] not in ('direct', 'nat'):
        raise ValueError('explicit public topology required')
    public = []
    for version, key in ((4, 'ipv4'), (6, 'ipv6')):
        if value['public'][key] is not None:
            address = deployment_address(value['public'][key], version)
            # Repository profile: currently allocated GUA block, not assignment proof.
            if (version == 6 and (address not in dep_ip.ip_network('2000::/3')
                    or address.is_reserved or address.is_site_local)):
                raise ValueError('unsupported public IPv6 GUA profile')
            if (not address.is_global and (version == 6 or value['public']['topology'] != 'nat'
                    or not any(address in dep_ip.ip_network(prefix) for prefix in DEP_PRIVATE4))
                    or any(address.version == network.version and address in network for network in admin_networks)):
                raise ValueError('unsupported public listener/topology')
            public.append({'version': version, 'address': str(address), 'interface': public_interface})
    if not public:
        raise ValueError('at least one explicit public listener required')
    deployment_fields(value['domains'], DEP_APPS)
    zone = deployment_domain(value['dns_zone'])
    domains = {app: deployment_domain(value['domains'][app]) for app in DEP_APPS}
    if len(set(domains.values())) != 4 or any(name == zone or not name.endswith('.' + zone) for name in domains.values()):
        raise ValueError('four distinct service names under the explicit zone required')
    deployment_fields(value['dns_nodes'], ('controller', 'authoritative-replica'))
    nodes = {role: deployment_text(value['dns_nodes'][role], r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', 63)
             for role in ('controller', 'authoritative-replica')}
    if len(set(nodes.values())) != 2:
        raise ValueError('distinct explicit DNS node identities required')
    deployment_fields(value['releases'], DEP_APPS)
    releases = {}
    for app in DEP_APPS:
        release = value['releases'][app]
        deployment_fields(release, ('commit', 'tree', 'manifest_sha256'))
        releases[app] = {key: deployment_text(release[key], r'[0-9a-f]{' + str(size) + '}', size)
                         for key, size in (('commit', 40), ('tree', 40), ('manifest_sha256', 64))}
    deployment_fields(value['private_ports'], DEP_PORT_NAMES)
    ports = value['private_ports']
    if (any(type(port) is not int or not 1024 <= port <= 65535 or port in (4190, 5432) for port in ports.values())
            or len(set(ports.values())) != len(ports)):
        raise ValueError('distinct bounded private backend ports required')
    deployment_fields(value['mail'], ('implicit_submission', 'pop3s', 'sieve'))
    if any(type(item) is not bool for item in value['mail'].values()):
        raise ValueError('explicit mail protocol switches required')
    return {'admin': admin, 'public': public, 'topology': value['public']['topology'],
            'domains': domains, 'dns_zone': zone, 'dns_nodes': nodes, 'releases': releases,
            'private_ports': dict(ports), 'mail': dict(value['mail'])}


def deployment_file(path, mode, content):
    data = content.encode('ascii')
    return {'file': path, 'mode': mode, 'bytes': len(data),
            'sha256': dep_policy_hash.sha256(data).hexdigest(), 'content': content}


def deployment_firewall(plan):
    lines = ['# Candidate only. No flush, load, interface assignment or hook admission.',
             'table inet azurelinux3s4 {', ' chain input {',
             '  type filter hook input priority 0; policy drop;', '  ct state invalid drop']
    for row in plan['admin']:
        family = 'ip' if ':' not in row['address'] else 'ip6'
        base = '  iifname "' + row['interface'] + '" ' + family
        lines.append(base + ' saddr { ' + ', '.join(row['routers']) + ' } tcp dport 22 drop')
        lines.append(base + ' saddr ' + row['prefix'] + ' ' + family + ' daddr ' + row['address'] + ' tcp dport 22 accept')
    # Check SSH before established/related and loopback admission: an old WAN
    # flow or router source must not inherit the general connection allowance.
    lines.extend(('  tcp dport 22 drop', '  iifname "lo" accept', '  ct state established,related accept',
                  '  icmp type { destination-unreachable, time-exceeded, parameter-problem, echo-request } accept',
                  '  icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request } accept'))
    for interface in sorted({row['interface'] for row in plan['admin'] + plan['public']}):
        lines.append('  iifname "' + interface + '" ip6 hoplimit 255 icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept')
        lines.append('  iifname "' + interface + '" ip6 hoplimit 1 icmpv6 type { mld-listener-query } accept')
    tcp = [25, 53, 80, 443, 587, 993]
    tcp.extend(port for name, port in (('implicit_submission', 465), ('pop3s', 995), ('sieve', 4190)) if plan['mail'][name])
    for row in plan['public']:
        base = '  iifname "' + row['interface'] + '" ' + ('ip' if row['version'] == 4 else 'ip6') + ' daddr ' + row['address']
        lines.append(base + ' tcp dport { ' + ', '.join(map(str, sorted(tcp))) + ' } accept')
        lines.append(base + ' udp dport 53 accept')
    lines.extend((' }', ' chain forward { type filter hook forward priority 0; policy drop; }',
                  ' chain output { type filter hook output priority 0; policy accept; }', '}', ''))
    return deployment_file('network/host.nft', '0600', '\n'.join(lines))


def deployment_applications(plan):
    # These contracts describe required independent publishes/configuration.
    # They do not interpret application JSON, grant file ownership, or emit an
    # untested generic sandbox for a JIT/network/database application.
    result = []
    for app in DEP_APPS:
        release = plan['releases'][app]
        directory = '/opt/' + app + '/releases/' + release['commit']
        configurations = {
            'mk8.sava': ['policy.env', 'application.env', 'gateway.env'],
            'mk8.drava': ['application.json', 'gateway.json'],
            'mk8.dns': ['control-plane.json', 'postgresql.connection', 'publisher.key'],
            'mk8.email': ['gateway.json', 'worker.json'],
        }[app]
        result.append({'application': app, 'domain': plan['domains'][app], 'release': release,
                       'release_directory': directory, 'runtime': '.NET 10', 'rid': 'linux-x64',
                       'configuration_files': ['/etc/' + app + '/' + name for name in configurations],
                       'mutable_directory': '/var/lib/' + app,
                       'requires_complete_publish_and_native_dependencies': True,
                       'configuration_contents_observed': False, 'release_contents_observed': False,
                       'unit_and_runtime_profile_admitted': False})
    return result


def deployment_bundle(data, ssh_producer):
    value, source = deployment_decode(data)
    plan = deployment_manifest(value)
    ssh = ssh_producer([row['prefix'] for row in plan['admin']], [row['address'] for row in plan['admin']])
    files = list(ssh['files'])
    files.append(deployment_firewall(plan))
    postgresql_files, postgresql_requirements = postgresql_profile()
    files.extend(postgresql_files)
    contract = {'applications': deployment_applications(plan), 'network': plan,
                'postgresql_prerequisites': postgresql_requirements,
                'port_owners': {'http_80_https_443': 'mk8.drava ONLY; no second nginx or static Web listener',
                               'dns_tcp_udp_53': 'mk8.dns authoritative Gateway; no public recursion',
                               'mail_tcp_25_587_993': 'mk8.email; optional ports require explicit manifest switches',
                               'ssh_tcp_22': 'dedicated admin daemon on exact declared admin listeners',
                               'postgresql_5432': 'loopback ONLY; mk8dns and mk8email independent roles/databases'},
                'private_backends': {key: {'address': '127.0.0.1', 'port': port} for key, port in plan['private_ports'].items()},
                'private_control_planes': {'mk8.drava': 'owned Unix-domain Application/Gateway IPC',
                                          'mk8.dns': 'owned Unix-domain Application/Gateway/Management IPC'},
                'storage': {'mk8.sava': 'owned SQLite/blob/encryption state; separate RPC key and Gateway scratch',
                            'mk8.drava': 'owned registry/ACME/enrollment/certificate state',
                            'mk8.dns': 'PostgreSQL controller state plus signed zone/journal/keys',
                            'mk8.email': 'PostgreSQL plus durable mail/spool/signing/encryption keys'},
                'backup_restore': 'All four application stores, PostgreSQL and key/certificate lineages need consistent off-host backup and tested restore.',
                'runtime': 'Distinct unprivileged users, protected releases/configuration, per-service writable paths and validated JIT/network/native profiles. Do not copy the static Web MDWE/PrivateNetwork sandbox.'}
    files.append(deployment_file('deployment/application-contract.json', '0600', dep_policy_json.dumps(contract, sort_keys=True, separators=(',', ':')) + '\n'))
    result = {'scope': 'EXPLICIT DEVELOPMENT CANDIDATE BYTES; NO ASSIGNMENT, INSTALLATION OR ACTIVATION',
              'source': source, 'manifest': plan, 'ssh_policy': ssh, 'files': files,
              'authority': {key: False for key in DEP_AUTHORITY},
              'prerequisites': [
                  'Owner-approved SAME actual topology/listener/interface/VLAN-parent/router/original-client/account/key authority and complete kernel/controller/hooks before activation. Declared private prefixes and CIDR membership prove no origin or assignment.',
                  'Native nftables/SSHD/PostgreSQL parsing, complete actual invocation/configuration and dual-family positive/refusal tests. Stateful related traffic, output acceptance and ICMP/ND admission are declarations, not isolation or anti-spoof proof.',
                  'Authenticate complete releases/runtime/native dependencies and all application configuration bytes; provision distinct users, secrets and application-specific services, enrollment/TLS/DNS/mail and health checks. Contract path spelling is prospective and must be adapted to authenticated release manifests.',
                  'Conflict-safe checked root destinations, atomic service/firewall transition and console recovery, actual durable boot/repair/update/rollback and consistent off-host backup/restore. No file applier, reservation, certificate issuance or reboot is supplied.',
              ],
              'limits': ['Source ownership and sequential repeated bytes/FD/path metadata are local observations under trusted root/base/Python/kernel and finite honest IO/scheduling, not credential-intent authority, content authenticity, atomicity, ABA protection or concurrent-root safety.',
                         'Each admin prefix is mandatory original manifest data, with no address allocation/default in tracked code. IPv4 private /24../30 and locally assigned ULA /64../126 are conservative declaration bounds. Null admin IPv6 omits that SSH listener/prefix; public IPv6 and required ICMPv6 remain independent. No all-RFC1918/ULA/link-local admin allowance or assignment/origin approval.',
                         'Firewall candidate contains no flush and was not loaded. Existing tables/hooks/TC/BPF/routes/NAT/proxy/VPN sources can affect semantics. Name-only interface matching does not bind ifindex/MAC/VLAN identity. Router exclusions do not establish direct original origin.',
                         'PostgreSQL peer/SCRAM and17+ feature prerequisites do not create roles/passwords/databases, authenticate a native server or local peer mappings, reconcile actual app connections, or grant SQL privileges. All server/update/SSH/Web/lifecycle and physical durability gates remain open.']}
    if len(dep_policy_json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii')) > 256 * 1024:
        raise ValueError('complete candidate output bound')
    return result


def deployment_main(ssh_producer):
    if len(dep_sys.argv) != 2:
        return 64
    try:
        dep_resource.setrlimit(dep_resource.RLIMIT_CPU, (20, 25))
        dep_resource.setrlimit(dep_resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        dep_resource.setrlimit(dep_resource.RLIMIT_CORE, (0, 0))
        result = deployment_bundle(deployment_read(dep_sys.argv[1]), ssh_producer)
        output = dep_policy_json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
    except (OSError, ValueError, TypeError, MemoryError, RecursionError, OverflowError):
        print('Deployment candidate refused', file=dep_sys.stderr)
        return 75
    print(output, end='')
    return 0

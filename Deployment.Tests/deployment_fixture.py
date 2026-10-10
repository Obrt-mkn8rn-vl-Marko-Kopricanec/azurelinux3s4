"""Synthetic network vectors, not address allocations or deployment defaults.

Only test modules import this file; it is neither packed nor used by production.
Deterministic digests derive unrelated finite private/GUA data from protocol
classes. No value comes from an owner's addressing, domains or router topology.
Names under .test in maintained fixtures are RFC 2606 reserved test DATA.
"""

import hashlib
import ipaddress


def seed(label):
    return hashlib.sha256(('azurelinux3s4-unassigned-test-data:' + label).encode('ascii')).digest()


def private4(label, protocol='10.0.0.0/8'):
    base = ipaddress.ip_network(protocol)
    available = (1 << (24 - base.prefixlen)) - 1
    offset = int.from_bytes(seed(label)[:3], 'big') % available + 1
    return ipaddress.ip_network((int(base.network_address) + (offset << 8), 24))


ADMIN4 = private4('admin')
NAT4 = private4('unrelated-private-ingress')
SECOND4 = private4('second-rfc1918-class', '192.168.0.0/16')
assert not ADMIN4.overlaps(NAT4)
# Locally assigned ULA class only, with synthetic digest bits. This is test DATA,
# not an RFC4193 allocation procedure or a proposed site prefix.
ADMIN6 = ipaddress.ip_network((int(ipaddress.ip_network('fd00::/8').network_address)
                               | (int.from_bytes(seed('admin-v6')[:5], 'big') << 80)
                               | (int.from_bytes(seed('subnet-v6')[:2], 'big') << 64), 64))


def admin4(offset=10):
    return str(ADMIN4.network_address + offset)


def admin6(offset=10, neighbor=False):
    return str(ADMIN6.network_address + offset + ((1 << 64) if neighbor else 0))


def nat4(offset=20):
    return str(NAT4.network_address + offset)


def second4(offset=2):
    return str(SECOND4.network_address + offset)


def noncanonical4():
    parts = admin4().split('.'); parts[1] = '0' + parts[1]
    return '.'.join(parts)


def mapped4():
    return str(ipaddress.IPv6Address((0xffff << 32) | int(ipaddress.IPv4Address(admin4()))))


def public_address(version, label):
    # Bounded native-classification-positive vectors; no mocked classifier,
    # DNS lookup, route/listener assignment, network IO or owner default.
    for counter in range(16):
        data = seed(label + ':' + str(counter))
        if version == 4:
            address = ipaddress.IPv4Address(int.from_bytes(data[:4], 'big'))
        else:
            base = int(ipaddress.ip_network('2000::/3').network_address)
            address = ipaddress.IPv6Address(base | (int.from_bytes(data[:16], 'big') & ((1 << 125) - 1)))
        if address.is_global and not (address.is_multicast or address.is_reserved or address.is_loopback or address.is_link_local):
            return str(address)
    raise AssertionError('finite synthetic native-classification vector unavailable')


PUBLIC4 = public_address(4, 'public-v4')
OTHER_PUBLIC4 = public_address(4, 'another-public-v4')
PUBLIC6 = public_address(6, 'public-v6')
assert PUBLIC4 != OTHER_PUBLIC4

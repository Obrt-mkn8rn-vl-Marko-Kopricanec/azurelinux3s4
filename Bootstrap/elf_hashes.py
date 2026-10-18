"""Finite SysV/GNU dynamic-symbol lookup table correspondence, as inert DATA."""

import hashlib
import struct


TAGS = {4, 0x6ffffef5}
ENTRY_LIMIT = 65536
BYTE_LIMIT = 4 * 1024 * 1024


def sysv_hash(name):
    value = 0
    for byte in name.encode('ascii'):
        value = (value << 4) + byte
        high = value & 0xf0000000
        value ^= high >> 24
        value &= ~high
    return value


def gnu_hash(name):
    value = 5381
    for byte in name.encode('ascii'):
        value = (value * 33 + byte) & 0xffffffff
    return value


def sysv_table(raw, symbols, required):
    if len(raw) < 8:
        raise ValueError('complete SysV hash header required')
    buckets_count, chains_count = struct.unpack_from('<II', raw)
    if (not 1 <= buckets_count <= ENTRY_LIMIT or chains_count != len(symbols)
            or len(raw) != 8 + 4 * (buckets_count + chains_count)):
        raise ValueError('bounded exact SysV hash dimensions required')
    words = struct.unpack_from('<' + 'I' * (buckets_count + chains_count), raw, 8)
    buckets, chains = words[:buckets_count], words[buckets_count:]
    if chains[0] or any(index >= chains_count for index in words):
        raise ValueError('bounded SysV bucket and chain indices required')
    visited = set()
    for bucket, first in enumerate(buckets):
        index = first
        while index:
            if index in visited or sysv_hash(symbols[index]['name']) % buckets_count != bucket:
                raise ValueError('acyclic unique name-corresponding SysV hash chains required')
            visited.add(index)
            index = chains[index]
    if not required <= visited or any(chains[index] for index in range(chains_count) if index not in visited):
        raise ValueError('complete exported SysV reachability and no orphan chains required')
    return {'kind': 'sysv', 'buckets': buckets_count, 'chains': chains_count,
            'reachable_symbols': len(visited), 'required_exports': len(required)}


def gnu_table(raw, symbols, required):
    if len(raw) < 16:
        raise ValueError('complete GNU hash header required')
    buckets_count, offset, bloom_count, shift = struct.unpack_from('<IIII', raw)
    if (not 1 <= buckets_count <= ENTRY_LIMIT or not 1 <= bloom_count <= ENTRY_LIMIT
            or bloom_count & (bloom_count - 1) or not 1 <= offset <= len(symbols) or shift >= 32):
        raise ValueError('bounded GNU buckets, symbol offset, power-of-two bloom and shift required')
    prefix = 16 + 8 * bloom_count + 4 * buckets_count
    if prefix > len(raw) or (len(raw) - prefix) % 4:
        raise ValueError('complete GNU bloom, bucket and chain arrays required')
    chains_count = (len(raw) - prefix) // 4
    if chains_count > ENTRY_LIMIT or chains_count and offset + chains_count != len(symbols):
        raise ValueError('complete GNU hashed symbol suffix required')
    bloom = struct.unpack_from('<' + 'Q' * bloom_count, raw, 16)
    buckets = struct.unpack_from('<' + 'I' * buckets_count, raw, 16 + 8 * bloom_count)
    chains = struct.unpack_from('<' + 'I' * chains_count, raw, prefix)
    visited = set()
    for bucket, first in enumerate(buckets):
        if first == 0:
            continue
        if not offset <= first < offset + chains_count:
            raise ValueError('GNU bucket must start within its complete chain suffix')
        index = first
        while True:
            if index >= offset + chains_count or index in visited:
                raise ValueError('finite disjoint terminated GNU hash chains required')
            visited.add(index)
            expected = gnu_hash(symbols[index]['name'])
            stored = chains[index - offset]
            if (stored | 1) != (expected | 1) or expected % buckets_count != bucket:
                raise ValueError('GNU stored hash and bucket must match the complete symbol name')
            mask = (1 << (expected % 64)) | (1 << ((expected >> shift) % 64))
            if bloom[(expected // 64) & (bloom_count - 1)] & mask != mask:
                raise ValueError('GNU bloom must retain both lookup bits for every chained symbol')
            if stored & 1:
                break
            index += 1
    if visited != set(range(offset, offset + chains_count)) or not required <= visited:
        raise ValueError('complete GNU chain suffix and exported symbol reachability required')
    return {'kind': 'gnu', 'buckets': buckets_count, 'chains': chains_count,
            'symbol_offset': offset, 'bloom_words': bloom_count, 'bloom_shift': shift,
            'reachable_symbols': len(visited), 'required_exports': len(required)}


def inspect(data, tags, sections, symbol_section, ranges, symbols, required, file_offset):
    if not TAGS.intersection(tags) or any(len(tags.get(tag, [])) > 1 for tag in TAGS):
        raise ValueError('at least one unique supported dynamic symbol hash table required')
    output = []
    ranges = list(ranges)
    for tag, kind, alignment, stride, parser in ((4, 5, 4, 4, sysv_table),
            (0x6ffffef5, 0x6ffffff6, 8, 0, gnu_table)):
        matches = [row for row in sections if row[1] == kind]
        if len(matches) != int(tag in tags):
            raise ValueError('exact dynamic hash tag and section correspondence required')
        if tag not in tags:
            continue
        _, _, flags, address, start, size, link, info, align, entry_size = matches[0]
        if (flags != 2 or address != tags[tag][0] or address % alignment or start % alignment
                or not 1 <= size <= BYTE_LIMIT or link != symbol_section or info != 0
                or align not in ((4, 8) if tag == 4 else (8,)) or address % align or start % align
                or entry_size != stride or file_offset(address, size) != start):
            raise ValueError('complete supported mapped hash section metadata required')
        ranges.append((start, start + size))
        raw = data[start:start + size]
        output.append({**parser(raw, symbols, required), 'bytes': size,
                       'sha256': hashlib.sha256(raw).hexdigest()})
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise ValueError('nonoverlapping complete hash and symbol metadata ranges required')
    return output

"""Bounded ELF64 GNU version declarations, without a loader or symbol lookup."""

import struct


VERSION_TAGS = {0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff}
RECORD_LIMIT = 8192
TABLE_LIMIT = 1024


def declarations(data, tags, strings, file_offset, text_at):
    ranges = []
    starts = set()

    def record(address, layout):
        if address % 4 or len(ranges) >= RECORD_LIMIT:
            raise ValueError('bounded aligned ELF version records required')
        size = struct.calcsize(layout)
        offset = file_offset(address, size)
        if offset in starts:
            raise ValueError('ELF version record reused or cyclic')
        starts.add(offset); ranges.append((offset, offset + size))
        return struct.unpack_from(layout, data, offset)

    def name(offset):
        value = text_at(strings, offset)
        if not value:
            raise ValueError('nonempty ELF version name required')
        return value

    def table(address_tag, count_tag):
        if address_tag not in tags and count_tag not in tags:
            return None, 0
        if (len(tags.get(address_tag, [])) != 1 or len(tags.get(count_tag, [])) != 1
                or not 1 <= tags[count_tag][0] <= TABLE_LIMIT):
            raise ValueError('complete unique bounded ELF version table pair required')
        return tags[address_tag][0], tags[count_tag][0]

    def following(address, relative, more, minimum):
        if (more and relative < minimum) or (not more and relative != 0):
            raise ValueError('ELF version chain/count termination mismatch')
        return address + relative

    needed, defined = [], []
    address, count = table(0x6ffffffe, 0x6fffffff)
    for index in range(count):
        version, entries, filename, auxiliary, next_row = record(address, '<HHIII')
        if version != 1 or not 1 <= entries <= RECORD_LIMIT or auxiliary < 16:
            raise ValueError('supported complete ELF version requirement required')
        library = name(filename)
        current, versions = address + auxiliary, []
        for inner in range(entries):
            hashed, flags, other, label, next_aux = record(current, '<IHHII')
            versions.append({'name': name(label), 'hash': hashed, 'flags': flags,
                             'weak': bool(flags & 2), 'index': other & 0x7fff,
                             'hidden_index_bit': bool(other & 0x8000)})
            current = following(current, next_aux, inner + 1 < entries, 16)
        needed.append({'library': library, 'versions': versions})
        address = following(address, next_row, index + 1 < count, 16)

    address, count = table(0x6ffffffc, 0x6ffffffd)
    for index in range(count):
        version, flags, number, entries, hashed, auxiliary, next_row = record(address, '<HHHHIII')
        if version != 1 or not 1 <= entries <= RECORD_LIMIT or auxiliary < 20:
            raise ValueError('supported complete ELF version definition required')
        current, names = address + auxiliary, []
        for inner in range(entries):
            label, next_aux = record(current, '<II')
            names.append(name(label))
            current = following(current, next_aux, inner + 1 < entries, 8)
        defined.append({'name': names[0], 'parents': names[1:], 'hash': hashed, 'flags': flags,
                        'base': bool(flags & 1), 'weak': bool(flags & 2), 'index': number & 0x7fff,
                        'hidden_index_bit': bool(number & 0x8000)})
        address = following(address, next_row, index + 1 < count, 20)

    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        raise ValueError('overlapping ELF version records')
    return needed, defined

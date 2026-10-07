import hashlib
import struct

EFFECT_TAGS = {}
for name, body, program, flags in (
    ("prein", 1023, 1085, 5020), ("postin", 1024, 1086, 5021),
    ("preun", 1025, 1087, 5022), ("postun", 1026, 1088, 5023),
    ("pretrans", 1151, 1153, 5024), ("posttrans", 1152, 1154, 5025),
    ("verify", 1079, 1091, 5026),
):
    EFFECT_TAGS.update({body: (name + "_body", 6, False),
                        program: (name + "_program", 8, True),
                        flags: (name + "_flags", 4, True)})
for name, body, program, flags, names, versions, senses, indexes, priority in (
    ("trigger", 1065, 1092, 5027, 1066, 1067, 1068, 1069, None),
    ("filetrigger", 5066, 5067, 5068, 5069, 5071, 5072, 5070, 5084),
    ("transfiletrigger", 5076, 5077, 5078, 5079, 5081, 5082, 5080, 5085),
):
    EFFECT_TAGS.update({body: (name + "_bodies", 8, False),
                        program: (name + "_programs", 8, True),
                        flags: (name + "_script_flags", 4, True),
                        names: (name + "_names", 8, False),
                        versions: (name + "_versions", 8, False),
                        senses: (name + "_senses", 4, True),
                        indexes: (name + "_indexes", 4, True)})
    if priority:
        EFFECT_TAGS[priority] = (name + "_priorities", 4, True)

def audit_header(material):
    # headerExport: two network-order uint32 sizes, 16-byte indexes, data.
    if not 8 <= len(material) <= 8 * 1024 * 1024:
        raise ValueError("effects header export exceeds its bound")
    entries, size = struct.unpack_from(">II", material)
    if not 0 < entries <= 65536 or 8 + 16 * entries + size != len(material):
        raise ValueError("effects header export layout is inconsistent")
    start, seen, tags = 8 + 16 * entries, set(), []
    for index in range(entries):
        tag, kind, offset, count = struct.unpack_from(">IIII", material, 8 + 16 * index)
        if tag not in EFFECT_TAGS:
            continue
        label, expected, disclose = EFFECT_TAGS[tag]
        scalar = tag in (1023, 1024, 1025, 1026, 1079, 1151, 1152,
                         5020, 5021, 5022, 5023, 5024, 5025, 5026)
        # RPM's HEADERGET_ARGV also accepts an ordinary interpreter encoded
        # as one scalar string. Genuine Azure headers commonly use this form.
        legacy_program = tag in (1085, 1086, 1087, 1088, 1091, 1153, 1154) and kind == 6 and count == 1
        if (tag in seen or (kind != expected and not legacy_program) or not 0 < count <= 4096
                or (scalar and count != 1) or offset >= size):
            raise ValueError("effects tag type/count/identity is unsupported: " + str(tag))
        seen.add(tag)
        cursor, values = start + offset, []
        if kind == 4:
            end = cursor + 4 * count
            if offset % 4 or end > len(material):
                raise ValueError("effects integer array exceeds the header")
            values = list(struct.unpack_from(">" + "I" * count, material, cursor))
            cursor = end
        else:
            for _ in range(count):
                end = material.find(b"\0", cursor)
                limit = 4096 if disclose else 1024 * 1024
                if end < cursor or end - cursor > limit:
                    raise ValueError("effects string is unterminated or excessive")
                value = material[cursor:end]
                values.append(value.decode("utf-8") if disclose else {
                    "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()})
                cursor = end + 1
        encoded = material[start + offset:cursor]
        tags.append({"tag": tag, "name": label, "type": kind, "count": count,
                     "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest(), "values": values})
    return {"header_bytes": len(material), "header_sha256": hashlib.sha256(material).hexdigest(),
            "tags": sorted(tags, key=lambda value: value["tag"])}

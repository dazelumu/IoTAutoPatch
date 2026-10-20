"""Small, structurally valid ELF fixtures; not magic bytes plus an ASan string."""
import struct


def elf_bytes(kind=2, *, asan=True, needed=None, bits=64, endian="<", defined=False):
    wide = bits == 64
    ehfmt = endian + ("16sHHIQQQIHHHHHH" if wide else "16sHHIIIIIHHHHHH")
    phfmt = endian + ("IIQQQQQQ" if wide else "IIIIIIII")
    shfmt = endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    syfmt = endian + ("IBBHQQ" if wide else "IIIBBH")
    dyfmt = endian + ("qQ" if wide else "iI")
    ehsize, phsize, shsize = map(struct.calcsize, (ehfmt, phfmt, shfmt))
    base = 0x400000
    phnum = 0 if kind == 1 else (2 if needed else 1)
    data = bytearray(ehsize + phnum * phsize)
    sections = [(0,) * 10]

    def append(payload, sh_type, flags=0, link=0, entsize=0):
        offset = len(data)
        data.extend(payload)
        sections.append((0, sh_type, flags, base + offset if flags & 2 else 0,
                         offset, len(payload), link, 0, 1, entsize))
        return offset, len(sections) - 1

    text_offset, _ = append(b"\xc3", 1, 6)
    _, strings = append(b"\0__asan_init\0" if asan else b"\0", 3)
    symbols = bytes(struct.calcsize(syfmt))
    if asan:
        entry = (1, 0x12, 0, 1 if defined else 0, base + text_offset if defined else 0, 1)
        if not wide:
            entry = (entry[0], entry[4], entry[5], entry[1], entry[2], entry[3])
        symbols += struct.pack(syfmt, *entry)
    append(symbols, 2, link=strings, entsize=struct.calcsize(syfmt))
    dynamic_offset, dynamic_size = 0, 0
    if needed:
        string_offset, dynstrings = append(b"\0" + needed.encode() + b"\0", 3, 2)
        tags = [(1, 1), (5, base + string_offset), (10, len(needed) + 2), (0, 0)]
        payload = b"".join(struct.pack(dyfmt, *t) for t in tags)
        dynamic_offset, _ = append(payload, 6, 2, dynstrings, struct.calcsize(dyfmt))
        dynamic_size = len(payload)
    shoff = len(data)
    for section in sections:
        data.extend(struct.pack(shfmt, *section))
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1 if endian == "<" else 2, 1]) + bytes(9)
    header = (ident, kind, 62 if wide else 3, 1, base + text_offset if kind != 1 else 0,
              ehsize if phnum else 0, shoff, 0, ehsize, phsize if phnum else 0, phnum,
              shsize, len(sections), 0)
    data[:ehsize] = struct.pack(ehfmt, *header)
    if phnum:
        entries = [(1, 5, 0, base, base, len(data), len(data), 0x1000)]
        if needed:
            entries.append((2, 4, dynamic_offset, base + dynamic_offset, base + dynamic_offset,
                            dynamic_size, dynamic_size, 8 if wide else 4))
        for index, entry in enumerate(entries):
            if not wide:
                entry = (entry[0], *entry[2:7], entry[1], entry[7])
            offset = ehsize + index * phsize
            data[offset:offset + phsize] = struct.pack(phfmt, *entry)
    return bytes(data)

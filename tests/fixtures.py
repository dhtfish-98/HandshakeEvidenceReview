"""Independent benign format writer; no runtime imports, sockets or real capture."""

import struct


def u16(n):
    return struct.pack(">H", n)


def extension(number, payload):
    return u16(number) + u16(len(payload)) + payload


def hello(kind=1, *, grease=True, extensions=True, duplicate=False, hrr=False):
    session = b"PRIVATE_SESSION"
    random = (
        bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
        if hrr
        else b"R" * 32
    )
    prefix = u16(771) + random + bytes([len(session)]) + session
    ids = [0xA0A, 0, 10, 11, 43] if grease else [0, 10, 11, 43]
    host = b"PRIVATE_HOST.example.invalid"
    values = {
        0xA0A: b"",
        0: u16(3 + len(host)) + b"\0" + u16(len(host)) + host,
        10: u16(6 if grease else 4) + (u16(0xA0A) if grease else b"") + u16(29) + u16(23),
        11: b"\x01\x00",
        43: b"\x04\x03\x04\x03\x03" if kind == 1 else u16(772),
    }
    if kind == 2:
        ids = [0xA0A, 43] if grease else [43]
    exts = b"".join(extension(number, values[number]) for number in ids)
    if duplicate:
        exts += extension(ids[0], values[ids[0]])
    if kind == 1:
        ciphers = (u16(0xA0A) if grease else b"") + u16(4865) + u16(4866)
        body = prefix + u16(len(ciphers)) + ciphers + b"\x01\x00"
    else:
        body = prefix + u16(4865) + b"\0"
    if extensions:
        body += u16(len(exts)) + exts
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def record(messages=None, kind=22, version=0x303):
    body = hello() if messages is None else messages
    return bytes([kind]) + u16(version) + u16(len(body)) + body


def frame(
    payload=None,
    *,
    link=1,
    ipv6=False,
    endian="<",
    port=443,
    fragment=False,
    vlan=0,
    ip_options=False,
    tcp_options=False,
):
    payload = record() if payload is None else payload
    tcp = (
        u16(12345) + u16(port) + bytes(8) + bytes([0x60 if tcp_options else 0x50, 0x18]) + bytes(6)
    )
    if tcp_options:
        tcp += bytes(4)
    tcp += payload
    if ipv6:
        tail = (b"\x06\0\0\0" + bytes(4)) if fragment else b""
        ip = (
            b"\x60\0\0\0"
            + u16(len(tail) + len(tcp))
            + bytes([44 if fragment else 6, 64])
            + bytes(range(16))
            + bytes(range(16, 32))
            + tail
            + tcp
        )
    else:
        extra = bytes(4) if ip_options else b""
        ip = (
            bytes([0x46 if ip_options else 0x45, 0])
            + u16(20 + len(extra) + len(tcp))
            + bytes(2)
            + u16(0x2000 if fragment else 0x4000)
            + b"\x40\x06\0\0"
            + bytes([10, 23, 17, 2, 10, 23, 17, 3])
            + extra
            + tcp
        )
    protocol = 0x86DD if ipv6 else 0x0800
    if link == 1:
        tags = b"".join(u16(0x8100) + u16(1) for _ in range(vlan))
        return bytes(12) + tags + u16(protocol) + ip
    if link == 113:
        return bytes(14) + u16(protocol) + ip
    if link == 276:
        return u16(protocol) + bytes(18) + ip
    if link in (0, 108):
        return struct.pack((">" if link == 108 else endian) + "I", 30 if ipv6 else 2) + ip
    return ip


def pcap(frames=None, *, endian="<", nanos=False, link=1, original=None, reserved=0):
    values = [frame(link=link, endian=endian)] if frames is None else frames
    output = struct.pack(
        endian + "IHHIIII",
        0xA1B23C4D if nanos else 0xA1B2C3D4,
        2,
        4,
        reserved,
        reserved,
        262144,
        link,
    )
    for raw in values:
        output += (
            struct.pack(endian + "IIII", 7, 3, len(raw), len(raw) if original is None else original)
            + raw
        )
    return output


def option(code, raw, endian="<"):
    return struct.pack(endian + "HH", code, len(raw)) + raw + bytes((-len(raw)) % 4)


def block(kind, raw, endian="<"):
    assert len(raw) % 4 == 0
    length = len(raw) + 12
    return struct.pack(endian + "II", kind, length) + raw + struct.pack(endian + "I", length)


def section(*, endian="<", minor=0, declared=-1, opts=b""):
    return block(
        0xA0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, minor, declared) + opts, endian
    )


def interface(*, endian="<", link=1, snap=262144, opts=b"", reserved=0):
    return block(1, struct.pack(endian + "HHI", link, reserved, snap) + opts, endian)


def enhanced(raw=None, *, endian="<", index=0, ticks=7000003, opts=b"", original=None):
    raw = frame() if raw is None else raw
    values = struct.pack(
        endian + "IIIII",
        index,
        ticks >> 32,
        ticks & 0xFFFFFFFF,
        len(raw),
        len(raw) if original is None else original,
    )
    return block(6, values + raw + bytes((-len(raw)) % 4) + opts, endian)


def pcapng(*, endian="<", opts=b"", raw=None, minor=0):
    return (
        section(endian=endian, minor=minor)
        + interface(endian=endian, opts=opts)
        + enhanced(raw, endian=endian)
    )

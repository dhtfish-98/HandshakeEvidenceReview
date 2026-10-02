"""Classic PCAP and finite PCAPNG SHB/IDB/EPB/SPB envelope readers."""

from .binary import Span
from .contracts import Gap, Stop

MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 10**6),
    b"\xd4\xc3\xb2\xa1": ("<", 10**6),
    b"\xa1\xb2\x3c\x4d": (">", 10**9),
    b"\x4d\x3c\xb2\xa1": ("<", 10**9),
}
SHB = b"\x0a\x0d\x0d\x0a"


def packet_metadata(ctx, packet, original, snaplen, link, endian, timestamp, interface, section):
    ctx.charge("packets", packet.start)
    if len(packet) > ctx.limits.packet_bytes:
        raise Stop("packet_bytes_budget", packet.start)
    if original != len(packet):
        ctx.issue(
            "capture_truncated"
            if original > len(packet)
            else "legacy_original_smaller_than_capture",
            packet.start,
        )
    if snaplen and len(packet) > snaplen:
        ctx.issue("capture_exceeds_declared_snaplen", packet.start)
    if timestamp is None:
        ctx.issue("packet_timestamp_absent", packet.start)
    return {
        "packet_offset": packet.start,
        "packet_size": len(packet),
        "packet_index": ctx.counts["packets"] - 1,
        "section": section,
        "interface": interface,
        "linktype": link,
        "timestamp": timestamp,
        "capture_endian": "little" if endian == "<" else "big",
    }


def classic(data, ctx):
    file = Span(data)
    file.check(0, 24, "truncated_pcap_header")
    endian, denominator = MAGICS[file.read(0, 4)]
    if (file.num(4, "H", endian), file.num(6, "H", endian)) != (2, 4):
        raise Gap("unsupported_pcap_version", 4)
    snaplen, network = file.num(16, "I", endian), file.num(20, "I", endian)
    if not snaplen:
        raise Gap("zero_pcap_snaplen", 16, "FAIL")
    link = network & 0xFFFF
    if network >> 16:
        ctx.issue("pcap_additional_link_information_uninterpreted", 20)
    # Historical reserved words are explicitly ignored by the PCAP format.
    ctx.charge("sections", 0)
    at = 24
    while at < len(file):
        file.check(at, 16, "truncated_pcap_packet_header")
        seconds, fractional, captured, original = (
            file.num(at + i, "I", endian) for i in (0, 4, 8, 12)
        )
        if fractional >= denominator:
            raise Gap("pcap_fraction_out_of_range", at + 4, "FAIL")
        packet = file.sub(at + 16, captured)
        stamp = {"numerator": seconds * denominator + fractional, "denominator": denominator}
        metadata = packet_metadata(ctx, packet, original, snaplen, link, endian, stamp, 0, 0)
        yield packet, metadata
        at += 16 + captured


def options(span, endian, ctx):
    at, seen, rows = 0, {}, []
    while at < len(span):
        span.check(at, 4, "truncated_pcapng_option")
        code, size = span.num(at, "H", endian), span.num(at + 2, "H", endian)
        if code == 0:
            if size or any(span.read(at + 4, len(span) - at - 4)):
                raise Gap("invalid_pcapng_option_end", span.start + at, "FAIL")
            break
        if len(rows) >= ctx.limits.options:
            raise Stop("options_budget", span.start + at)
        padded = (size + 3) & ~3
        span.check(at + 4, padded, "pcapng_option_out_of_bounds")
        if any(span.read(at + 4 + size, padded - size)):
            raise Gap("nonzero_pcapng_option_padding", span.start + at + 4 + size, "FAIL")
        value = span.sub(at + 4, size)
        seen[code] = seen.get(code, 0) + 1
        rows.append((code, value))
        at += 4 + padded
    return rows, seen


def idb(block, endian, ctx):
    block.check(0, 20, "truncated_pcapng_interface")
    link, snap = block.num(8, "H", endian), block.num(12, "I", endian)
    denominator, offset = 10**6, 0
    rows, counts = options(block.sub(16, len(block) - 20), endian, ctx)
    sizes = {4: 8, 5: 17, 6: 6, 7: 8, 8: 8, 9: 1, 10: 4, 13: 1, 14: 8, 16: 8, 17: 8}
    repeatable = {1, 4, 5}
    for code, value in rows:
        if code in sizes and len(value) != sizes[code]:
            raise Gap("invalid_interface_option_size", value.start, "FAIL")
        if code in range(1, 19) and code not in repeatable and counts[code] > 1:
            raise Gap("duplicate_interface_option", value.start, "FAIL")
        if code == 9:
            resolution = value.u8(0)
            denominator = (2 if resolution & 128 else 10) ** (resolution & 127)
        elif code == 14:
            offset = value.num(0, "q", endian)
        elif code == 13 and value.u8(0):
            ctx.issue("interface_fcs_bits_uninterpreted", value.start)
        elif code == 11 and not len(value):
            raise Gap("empty_interface_filter_option", value.start, "FAIL")
        elif code not in range(1, 19):
            ctx.issue("unknown_interface_option_opaque", value.start)
    # The interface reserved word is ignored, including historical nonzero values.
    return {"link": link, "snap": snap, "denominator": denominator, "offset": offset}


def enhanced(block, endian, interfaces, ctx, section):
    block.check(0, 32, "truncated_pcapng_enhanced_packet")
    index, hi, lo, captured, original = (block.num(i, "I", endian) for i in (8, 12, 16, 20, 24))
    if index >= len(interfaces):
        raise Gap("undefined_pcapng_interface", block.start + 8, "FAIL")
    interface = interfaces[index]
    padded = (captured + 3) & ~3
    block.check(28, padded + 4, "pcapng_packet_out_of_bounds")
    if any(block.read(28 + captured, padded - captured)):
        raise Gap("nonzero_pcapng_packet_padding", block.start + 28 + captured, "FAIL")
    rows, counts = options(block.sub(28 + padded, len(block) - 32 - padded), endian, ctx)
    for code, value in rows:
        fixed_sizes = {2: 4, 4: 8, 5: 8, 6: 4, 8: 8}
        if code in fixed_sizes and (
            len(value) != fixed_sizes[code] or code != 8 and counts[code] > 1
        ):
            raise Gap("invalid_packet_option", value.start, "FAIL")
        if code in (3, 7):
            if not len(value):
                raise Gap("empty_packet_hash_or_verdict", value.start, "FAIL")
            subtype = value.u8(0)
            expected = ({2: 5, 3: 17, 4: 21, 5: 5} if code == 3 else {1: 9, 2: 9}).get(subtype)
            if expected is not None and len(value) != expected:
                raise Gap("invalid_packet_hash_or_verdict_size", value.start, "FAIL")
            ctx.issue("packet_hash_or_verdict_semantics_opaque", value.start)
        if code == 2 and value.num(0, "I", endian) & ~0x1F:
            ctx.issue("packet_fcs_offload_or_error_flags_uninterpreted", value.start)
        elif code == 4 and value.num(0, "Q", endian):
            ctx.issue("observed_packet_drop_count", value.start)
        elif code not in (1, 2, 3, 4, 5, 6, 7, 8):
            ctx.issue("unknown_packet_option_opaque", value.start)
    packet = block.sub(28, captured)
    denominator = interface["denominator"]
    stamp = {
        "numerator": (hi << 32 | lo) + interface["offset"] * denominator,
        "denominator": denominator,
    }
    return packet, packet_metadata(
        ctx, packet, original, interface["snap"], interface["link"], endian, stamp, index, section
    )


def simple(block, endian, interfaces, ctx, section):
    block.check(0, 16, "truncated_pcapng_simple_packet")
    if not interfaces:
        raise Gap("undefined_pcapng_interface", block.start + 8, "FAIL")
    interface = interfaces[0]
    original = block.num(8, "I", endian)
    captured = min(original, interface["snap"]) if interface["snap"] else original
    if 16 + ((captured + 3) & ~3) != len(block):
        raise Gap("invalid_simple_packet_size", block.start + 4, "FAIL")
    if any(block.read(12 + captured, len(block) - 16 - captured)):
        raise Gap("nonzero_pcapng_packet_padding", block.start + 12 + captured, "FAIL")
    packet = block.sub(12, captured)
    return packet, packet_metadata(
        ctx, packet, original, interface["snap"], interface["link"], endian, None, 0, section
    )


def pcapng(data, ctx):
    file = Span(data)
    at, endian, interfaces, section_end = 0, None, [], None
    while at < len(file):
        ctx.charge("blocks", at)
        file.check(at, 12, "truncated_pcapng_block")
        is_section = file.read(at, 4) == SHB
        if section_end is not None and (at > section_end or at == section_end and not is_section):
            raise Gap("pcapng_section_length_mismatch", at, "FAIL")
        if is_section:
            if section_end is not None and at != section_end:
                raise Gap("pcapng_section_length_mismatch", at, "FAIL")
            magic = file.read(at + 8, 4)
            endian = (
                ">"
                if magic == b"\x1a\x2b\x3c\x4d"
                else "<"
                if magic == b"\x4d\x3c\x2b\x1a"
                else None
            )
            if endian is None:
                raise Gap("invalid_pcapng_byte_order_magic", at + 8, "FAIL")
        elif endian is None:
            raise Gap("pcapng_section_header_required", at, "FAIL")
        kind, size = file.num(at, "I", endian), file.num(at + 4, "I", endian)
        if size < 12 or size % 4:
            raise Gap("invalid_pcapng_block_length", at + 4, "FAIL")
        block = file.sub(at, size)
        if block.num(size - 4, "I", endian) != size:
            raise Gap("pcapng_repeated_length_mismatch", at + size - 4, "FAIL")
        if is_section:
            block.check(0, 28, "truncated_pcapng_section_header")
            major, minor = block.num(12, "H", endian), block.num(14, "H", endian)
            if major != 1 or minor not in (0, 2):
                raise Gap("unsupported_pcapng_version", at + 12)
            declared = block.num(16, "q", endian)
            if declared < -1 or declared >= 0 and declared % 4:
                raise Gap("invalid_pcapng_section_length", at + 16, "FAIL")
            section_end = None if declared == -1 else at + size + declared
            if section_end is not None and section_end > len(file):
                raise Gap("pcapng_section_length_out_of_bounds", at + 16, "FAIL")
            rows, counts = options(block.sub(24, size - 28), endian, ctx)
            for code, value in rows:
                if code in (2, 3, 4) and counts[code] > 1:
                    raise Gap("duplicate_section_option", value.start, "FAIL")
                if code not in (1, 2, 3, 4):
                    ctx.issue("unknown_section_option_opaque", value.start)
            interfaces = []
            ctx.charge("sections", at)
        elif section_end is not None and at + size > section_end:
            raise Gap("pcapng_block_crosses_section", at, "FAIL")
        elif kind == 1:
            if len(interfaces) >= ctx.limits.interfaces:
                raise Stop("interfaces_budget", at)
            interfaces.append(idb(block, endian, ctx))
        elif kind == 6:
            yield enhanced(block, endian, interfaces, ctx, ctx.counts["sections"] - 1)
        elif kind == 3:
            yield simple(block, endian, interfaces, ctx, ctx.counts["sections"] - 1)
        else:
            ctx.issue("unknown_pcapng_block_opaque", at)
        at += size
    if section_end is not None and at != section_end:
        raise Gap("pcapng_section_length_mismatch", at, "FAIL")


def capture(data, ctx):
    if data[:4] in MAGICS:
        return "PCAP", classic(data, ctx)
    if data[:4] == SHB:
        return "PCAPNG", pcapng(data, ctx)
    raise Gap("unsupported_capture_format", 0)

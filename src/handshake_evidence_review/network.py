"""Finite link/IP/TCP envelope extraction; no flow or IP-fragment reassembly."""

from .contracts import Gap


def complete(span, offset, size, code):
    if offset + size > len(span):
        raise Gap(code, span.start + offset)


def tcp_payload(packet, metadata, ctx):
    link, endian = metadata["linktype"], "<" if metadata["capture_endian"] == "little" else ">"
    if link == 1:
        complete(packet, 0, 14, "truncated_ethernet_header")
        protocol, at = packet.u16(12), 14
        tags = 0
        while protocol in (0x8100, 0x88A8, 0x9100):
            if tags == 2:
                raise Gap("unsupported_vlan_depth", packet.start + at)
            complete(packet, at, 4, "truncated_vlan_header")
            protocol = packet.u16(at + 2)
            tags += 1
            at += 4
    elif link == 113:
        complete(packet, 0, 16, "truncated_sll_header")
        if packet.u16(4) > 8:
            raise Gap("unsupported_sll_address_length", packet.start + 4)
        protocol, at = packet.u16(14), 16
    elif link == 276:
        complete(packet, 0, 20, "truncated_sll2_header")
        if packet.u16(2) or packet.u8(11) > 8:
            raise Gap("unsupported_sll2_header_fields", packet.start + 2)
        protocol, at = packet.u16(0), 20
    elif link in (0, 108):
        complete(packet, 0, 4, "truncated_loopback_header")
        family = packet.num(0, "I", ">" if link == 108 else endian)
        protocol, at = (0x0800 if family == 2 else 0x86DD if family in (24, 28, 30) else None), 4
        if protocol is None:
            raise Gap("unsupported_loopback_family", packet.start)
    elif link == 101:
        complete(packet, 0, 1, "truncated_raw_ip_header")
        version = packet.u8(0) >> 4
        protocol, at = 0x0800 if version == 4 else 0x86DD if version == 6 else None, 0
        if protocol is None:
            raise Gap("unsupported_raw_ip_version", packet.start)
    else:
        raise Gap("unsupported_linktype", packet.start)
    if protocol not in (0x0800, 0x86DD):
        return None
    ip = packet.sub(at, len(packet) - at)
    if protocol == 0x0800:
        complete(ip, 0, 20, "truncated_ipv4_header")
        header = (ip.u8(0) & 15) * 4
        length = ip.u16(2)
        if ip.u8(0) >> 4 != 4 or header < 20 or length < header:
            raise Gap("invalid_ipv4_header", ip.start, "FAIL")
        complete(ip, 0, header, "truncated_ipv4_options")
        if length > len(ip):
            raise Gap("truncated_ipv4_datagram", ip.start)
        fragments = ip.u16(6)
        if fragments & 0x8000:
            ctx.issue("unsupported_ipv4_reserved_flag", ip.start + 6)
        if fragments & 0x3FFF:
            raise Gap("ipv4_fragment_reassembly_required", ip.start + 6)
        if header > 20:
            ctx.issue("ipv4_options_opaque", ip.start + 20)
        if ip.u8(9) != 6:
            return None
        tcp = ip.sub(header, length - header)
    else:
        complete(ip, 0, 40, "truncated_ipv6_header")
        if ip.u8(0) >> 4 != 6:
            raise Gap("invalid_ipv6_version", ip.start, "FAIL")
        length, next_header, header = ip.u16(4), ip.u8(6), 40
        if not length:
            raise Gap("ipv6_zero_payload_or_jumbogram_unsupported", ip.start + 4)
        if length + 40 > len(ip):
            raise Gap("truncated_ipv6_datagram", ip.start)
        ip = ip.sub(0, length + 40)
        count = 0
        while next_header in (0, 43, 60):
            if count >= 8:
                raise Gap("ipv6_extension_depth_budget", ip.start + header)
            complete(ip, header, 8, "truncated_ipv6_extension_header")
            size = (ip.u8(header + 1) + 1) * 8
            complete(ip, header, size, "ipv6_extension_out_of_bounds")
            ctx.issue("ipv6_extension_semantics_opaque", ip.start + header)
            next_header, header, count = ip.u8(header), header + size, count + 1
        if next_header in (44, 50, 51):
            raise Gap("ipv6_fragment_or_protected_payload_unsupported", ip.start + header)
        if next_header != 6:
            return None
        tcp = ip.sub(header, len(ip) - header)
    complete(tcp, 0, 20, "truncated_tcp_header")
    source, destination = tcp.u16(0), tcp.u16(2)
    header = (tcp.u8(12) >> 4) * 4
    if header < 20:
        raise Gap("invalid_tcp_data_offset", tcp.start + 12, "FAIL")
    complete(tcp, 0, header, "truncated_tcp_options")
    if header > 20:
        ctx.issue("tcp_options_opaque", tcp.start + 20)
    if not ctx.any_port and source != 443 and destination != 443:
        return None
    return tcp.sub(header, len(tcp) - header)

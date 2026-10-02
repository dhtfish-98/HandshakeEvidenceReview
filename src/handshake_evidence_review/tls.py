"""Bounded plaintext record/hello envelopes and original JA3/JA3S tag formulae."""

import hashlib
from .binary import Cursor
from .contracts import Gap, Stop

GREASE = frozenset(range(0x0A0A, 0xFAFA + 1, 0x1010))
HRR = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def words(span, limits, minimum=0):
    if len(span) < minimum or len(span) % 2:
        raise Gap("invalid_u16_vector", span.start, "FAIL")
    if len(span) // 2 > limits.vector_entries:
        raise Stop("vector_entries_budget", span.start)
    return [span.u16(i) for i in range(0, len(span), 2)]


def parse_hello(body, kind, ctx):
    cursor = Cursor(body)
    version = cursor.uint(2)
    random = cursor.take(32).read(0, 32)
    session = cursor.vector(1)
    if len(session) > 32:
        raise Gap("session_id_too_long", session.start, "FAIL")
    if kind == 1:
        cipher_span = cursor.vector(2)
        ciphers = words(cipher_span, ctx.limits, 2)
        compression = cursor.vector(1)
        if not len(compression):
            raise Gap("empty_compression_vector", compression.start, "FAIL")
    else:
        ciphers = [cursor.uint(2)]
        cursor.uint(1)
    ids, groups, formats, versions = [], [], [], []
    if cursor.pos < len(body):
        extension_span = cursor.vector(2)
        cursor.done()
        extensions = Cursor(extension_span)
        while extensions.pos < len(extension_span):
            if len(ids) >= ctx.limits.extensions:
                raise Stop("extensions_budget", extension_span.start + extensions.pos)
            at = extension_span.start + extensions.pos
            number = extensions.uint(2)
            payload = extensions.vector(2)
            if number in ids:
                raise Gap("duplicate_tls_extension", at, "FAIL")
            ids.append(number)
            field = Cursor(payload)
            if number == 10 and kind == 1:
                groups = words(field.vector(2), ctx.limits, 2)
                field.done()
            elif number == 11 and kind == 1:
                raw_formats = field.vector(1)
                if not len(raw_formats):
                    raise Gap("empty_point_formats", raw_formats.start, "FAIL")
                if len(raw_formats) > ctx.limits.vector_entries:
                    raise Stop("vector_entries_budget", raw_formats.start)
                formats = list(raw_formats.read(0, len(raw_formats)))
                field.done()
            elif number == 43:
                versions = words(field.vector(1), ctx.limits, 2) if kind == 1 else [field.uint(2)]
                field.done()
    cursor.done()

    def clean(numbers):
        return "-".join(str(n) for n in numbers if n not in GREASE)

    if kind == 1:
        tag = ",".join(
            (str(version), clean(ciphers), clean(ids), clean(groups), "-".join(map(str, formats)))
        )
    else:
        # Preserve original JA3S extension IDs, including GREASE. This is a
        # compatibility tag, not validation that a server negotiated legally.
        tag = ",".join((str(version), str(ciphers[0]), "-".join(map(str, ids))))
    return {
        "kind": "JA3" if kind == 1 else "JA3S",
        "tag": tag,
        "md5_compatibility": hashlib.md5(tag.encode("ascii"), usedforsecurity=False).hexdigest(),
        "legacy_version": version,
        "supported_versions_observed": versions,
        "server_variant": "hello_retry_request"
        if kind == 2 and random == HRR
        else "server_hello"
        if kind == 2
        else None,
        "extension_ids_observed": ids,
        "hello_offset": body.start - 4,
        "hello_size": len(body) + 4,
        "body_offset": body.start,
        "body_size": len(body),
        "body_sha256": hashlib.sha256(body.read(0, len(body))).hexdigest(),
        "private_values": "random_session_sni_and_extension_payloads_omitted",
        "evidence": "COMPLETE_HELLO_ENVELOPE_HYPOTHESIS_UNAUTHENTICATED",
    }


def walk_tls(payload, ctx, metadata):
    at = 0
    while at < len(payload):
        ctx.charge("tls_records", payload.start + at)
        remaining = len(payload) - at
        if remaining < 5:
            ctx.issue("partial_tls_record_header_reassembly_required", payload.start + at)
            return
        content_type, version, size = payload.u8(at), payload.u16(at + 1), payload.u16(at + 3)
        if content_type not in (20, 21, 22, 23):
            ctx.issue("unrecognized_tcp_payload_or_continuation", payload.start + at)
            return
        if version not in (0x301, 0x302, 0x303):
            ctx.issue("unsupported_tls_record_version", payload.start + at + 1)
            return
        if size > (16384 if content_type == 22 else 18432):
            ctx.issue("unsupported_tls_record_size", payload.start + at + 3)
            return
        if size + 5 > remaining:
            ctx.issue("partial_tls_record_body_reassembly_required", payload.start + at)
            return
        record = payload.sub(at + 5, size)
        if content_type == 22:
            if size == 0:
                ctx.issue("zero_length_handshake_record", record.start, "FAIL")
            message_at = 0
            while message_at < len(record):
                ctx.charge("handshakes", record.start + message_at)
                if len(record) - message_at < 4:
                    ctx.issue(
                        "partial_handshake_header_reassembly_required", record.start + message_at
                    )
                    break
                kind, message_size = record.u8(message_at), record.u24(message_at + 1)
                if message_size + 4 > len(record) - message_at:
                    ctx.issue(
                        "partial_handshake_body_reassembly_required", record.start + message_at
                    )
                    break
                if kind in (1, 2):
                    body = record.sub(message_at + 4, message_size)
                    try:
                        item = parse_hello(body, kind, ctx)
                        item["hello_sha256"] = hashlib.sha256(
                            record.read(message_at, message_size + 4)
                        ).hexdigest()
                        item.update(metadata)
                        item["record_offset"] = payload.start + at
                        ctx.hello(item)
                    except Stop:
                        raise
                    except Gap as gap:
                        ctx.issue(gap.code, gap.offset, gap.status)
                else:
                    ctx.issue("non_hello_handshake_opaque", record.start + message_at)
                message_at += message_size + 4
        elif content_type == 23:
            ctx.issue("encrypted_or_application_record_opaque", payload.start + at)
        elif content_type == 20:
            if size != 1 or record.u8(0) != 1:
                ctx.issue("invalid_change_cipher_spec_envelope", record.start, "FAIL")
            else:
                ctx.issue("change_cipher_spec_cipher_state_unresolved", record.start)
                return
        else:
            ctx.issue(
                "unsupported_alert_envelope" if size != 2 else "alert_semantics_opaque",
                record.start,
            )
        at += size + 5

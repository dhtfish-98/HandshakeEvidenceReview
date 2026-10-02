"""Immutable bytes API with definite failures preserved across coverage gaps."""

import hashlib
from .capture import capture
from .contracts import Gap, Ledger, Limits, Stop, encode_report
from .network import tcp_payload
from .tls import walk_tls


def review_bytes(data, *, limits=None, any_port=False):
    if type(data) is not bytes:
        raise ValueError("immutable_bytes_required")
    if limits is None:
        limits = Limits()
    if type(limits) is not Limits or type(any_port) is not bool:
        raise ValueError("invalid_review_options")
    ctx = Ledger(limits, any_port)
    if len(data) > limits.input_bytes:
        ctx.issue("input_bytes_budget", 0)
        return ctx.finish(None, len(data), None)
    digest, capture_format = hashlib.sha256(data).hexdigest(), None
    try:
        capture_format, packets = capture(data, ctx)
        for packet, metadata in packets:
            try:
                payload = tcp_payload(packet, metadata, ctx)
                if payload is not None and len(payload):
                    walk_tls(payload, ctx, metadata)
            except Stop:
                raise
            except Gap as gap:
                ctx.issue(gap.code, gap.offset, gap.status)
    except Gap as gap:
        ctx.issue(gap.code, gap.offset, gap.status)
    return ctx.finish(digest, len(data), capture_format)


__all__ = ["review_bytes", "encode_report"]

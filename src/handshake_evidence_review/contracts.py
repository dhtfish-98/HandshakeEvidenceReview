"""Finite offline evidence profile; fingerprint tags are not authentication."""

from dataclasses import asdict, dataclass, fields
import json


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 16 * 1024 * 1024
    packets: int = 8192
    blocks: int = 16384
    sections: int = 64
    interfaces: int = 64
    packet_bytes: int = 262144
    tls_records: int = 16384
    handshakes: int = 4096
    extensions: int = 512
    vector_entries: int = 2048
    options: int = 256
    findings: int = 512
    report_bytes: int = 1024 * 1024

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            minimum = 2048 if field.name == "report_bytes" else 1
            if type(value) is not int or not minimum <= value <= field.default:
                raise ValueError("invalid_limits")


ASSUMPTIONS = {
    key: "OPEN"
    for key in (
        "capture_authenticity",
        "wire_checksum_integrity",
        "tcp_flow_completeness",
        "tls_protocol_semantics_and_authentication",
        "peer_identity",
        "fingerprint_maliciousness_or_safety",
        "cvp_eligibility",
    )
}


class Gap(Exception):
    def __init__(self, code, offset, status="OPEN"):
        self.code, self.offset, self.status = code, offset, status


class Stop(Gap):
    pass


class Ledger:
    def __init__(self, limits, any_port):
        self.limits, self.any_port = limits, any_port
        self.counts = {k: 0 for k in ("packets", "blocks", "sections", "tls_records", "handshakes")}
        self.findings, self.hellos = [], []
        self.fail = self.open = False
        self.output_charge = 1024

    def issue(self, code, offset, status="OPEN"):
        self.fail |= status == "FAIL"
        self.open |= status == "OPEN"
        if len(self.findings) < self.limits.findings:
            self.findings.append({"code": code, "offset": offset, "status": status})
        else:
            self.open = True

    def charge(self, kind, offset):
        self.counts[kind] += 1
        if self.counts[kind] > getattr(self.limits, kind):
            raise Stop(kind + "_budget", offset)

    def hello(self, item):
        self.output_charge += len(encode_report(item))
        if self.output_charge > self.limits.report_bytes:
            raise Stop("report_bytes_budget", item["hello_offset"])
        self.hellos.append(item)

    def finish(self, digest, size, capture_format):
        if not self.hellos:
            self.issue("no_complete_hello_observed", 0)
        result = {
            "project": "HandshakeEvidenceReview",
            "version": "0.1.0",
            "status": "FAIL" if self.fail else "OPEN" if self.open else "PASS",
            "meaning": "bounded_capture_and_fingerprint_profile_only",
            "input": {"bytes": size, "sha256": digest, "format": capture_format},
            "any_port": self.any_port,
            "limits": asdict(self.limits),
            "counts": self.counts,
            "hellos": self.hellos,
            "findings": self.findings,
            "known_format_failure": self.fail,
            "assumptions": dict(ASSUMPTIONS),
        }
        if len(encode_report(result)) > self.limits.report_bytes:
            result["status"] = "FAIL" if self.fail else "OPEN"
            result["hellos"] = []
            result["findings"] = [{"status": "OPEN", "code": "report_bytes_budget", "offset": 0}]
            if self.fail:
                result["findings"].append(
                    {"status": "FAIL", "code": "known_format_failure_retained", "offset": 0}
                )
        return result


def encode_report(report):
    return (
        json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")

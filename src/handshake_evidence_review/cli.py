"""One explicit offline capture, bounded JSON stdout and sanitized diagnostics."""

import argparse
import sys
from .contracts import Limits, encode_report
from .files import InputUnavailable, snapshot
from .review import review_bytes


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "HandshakeEvidenceReview: invalid_arguments\n")


def main(argv=None):
    parser = Parser(
        prog="handshake-evidence-review",
        description="Bounded offline PCAP/PCAPNG hello fingerprint evidence.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version="HandshakeEvidenceReview 0.1.2")
    parser.add_argument("capture")
    parser.add_argument(
        "--any-port",
        action="store_true",
        help="Inspect TCP payloads beyond the default port 443 profile.",
    )
    parser.add_argument("--max-input-bytes", type=int, default=Limits.input_bytes)
    args = parser.parse_args(argv)
    try:
        limits = Limits(input_bytes=args.max_input_bytes)
        data = snapshot(args.capture, limits.input_bytes)
        result = review_bytes(data, limits=limits, any_port=args.any_port)
    except InputUnavailable as error:
        print("HandshakeEvidenceReview: " + error.code, file=sys.stderr)
        return 2
    except ValueError:
        print("HandshakeEvidenceReview: invalid_options", file=sys.stderr)
        return 2
    try:
        sys.stdout.buffer.write(encode_report(result))
    except BrokenPipeError:
        return 2
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[result["status"]]

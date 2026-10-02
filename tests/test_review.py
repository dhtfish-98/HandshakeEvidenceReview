import hashlib
import json
import random
import struct
import sys
import unittest
from unittest.mock import patch
from handshake_evidence_review import Limits, encode_report, review_bytes
from fixtures import (
    block,
    enhanced,
    extension,
    frame,
    hello,
    interface,
    option,
    pcap,
    pcapng,
    record,
    section,
    u16,
)


class ReviewTests(unittest.TestCase):
    def codes(self, report):
        return {row["code"] for row in report["findings"]}

    def test_known_client_server_tags_and_md5(self):
        data = pcap([frame(record(hello(1) + hello(2)))])
        report = review_bytes(data)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(
            [r["tag"] for r in report["hellos"]],
            ["771,4865-4866,0-10-11-43,29-23,0", "771,4865,2570-43"],
        )
        for row in report["hellos"]:
            self.assertEqual(
                row["md5_compatibility"],
                hashlib.md5(row["tag"].encode(), usedforsecurity=False).hexdigest(),
            )
            for kind in ("hello", "body"):
                raw = data[row[kind + "_offset"] : row[kind + "_offset"] + row[kind + "_size"]]
                self.assertEqual(row[kind + "_sha256"], hashlib.sha256(raw).hexdigest())

    def test_classic_all_endian_and_timestamp_magic(self):
        for endian in "<>":
            for nanos in (False, True):
                r = review_bytes(pcap(endian=endian, nanos=nanos))
                self.assertEqual(r["status"], "PASS")
                denominator = 10**9 if nanos else 10**6
                self.assertEqual(
                    r["hellos"][0]["timestamp"],
                    {"numerator": 7 * denominator + 3, "denominator": denominator},
                )

    def test_historical_reserved_words_are_ignored(self):
        self.assertEqual(review_bytes(pcap(reserved=0xFFFFFFFF))["status"], "PASS")

    def test_pcap_header_version_snaplen_fraction_and_truncation(self):
        base = pcap()
        for offset, fmt, value in ((16, "I", 0), (28, "I", 1000000)):
            raw = bytearray(base)
            struct.pack_into("<" + fmt, raw, offset, value)
            self.assertEqual(review_bytes(bytes(raw))["status"], "FAIL")
        raw = bytearray(base)
        struct.pack_into("<H", raw, 4, 3)
        self.assertEqual(review_bytes(bytes(raw))["status"], "OPEN")
        self.assertEqual(review_bytes(base[:23])["status"], "FAIL")
        self.assertEqual(review_bytes(base[:-1])["status"], "FAIL")

    def test_unknown_format_and_no_complete_hello(self):
        for raw in (b"", b"not a capture", pcap([]), pcap([frame(b"")])):
            self.assertEqual(review_bytes(raw)["status"], "OPEN")

    def test_supported_link_types_v4_and_v6(self):
        for link in (1, 113, 276, 0, 108, 101):
            for ipv6 in (False, True):
                for endian in "<>":
                    data = pcap(
                        [frame(link=link, ipv6=ipv6, endian=endian)], link=link, endian=endian
                    )
                    self.assertEqual(review_bytes(data)["status"], "PASS", (link, ipv6, endian))

    def test_vlan_depth(self):
        for count, status in ((1, "PASS"), (2, "PASS"), (3, "OPEN")):
            self.assertEqual(review_bytes(pcap([frame(vlan=count)]))["status"], status)

    def test_ip_fragment_and_options_require_open(self):
        for ipv6 in (False, True):
            self.assertEqual(
                review_bytes(pcap([frame(ipv6=ipv6, fragment=True)]))["status"], "OPEN"
            )
        for kwargs in ({"ip_options": True}, {"tcp_options": True}):
            self.assertEqual(review_bytes(pcap([frame(**kwargs)]))["status"], "OPEN")

    def test_legitimate_capture_prefixes_are_open(self):
        full = frame()
        for cut in (0, 1, 13, 14, 20, 33, 34, 40, 53, len(full) - 1):
            self.assertEqual(review_bytes(pcap([full[:cut]], original=len(full)))["status"], "OPEN")

    def test_original_smaller_than_capture_is_legacy_open(self):
        self.assertEqual(review_bytes(pcap(original=1))["status"], "OPEN")

    def test_any_port_is_explicit(self):
        data = pcap([frame(port=8443)])
        self.assertEqual(review_bytes(data)["status"], "OPEN")
        self.assertEqual(review_bytes(data, any_port=True)["status"], "PASS")

    def test_invalid_ip_and_tcp_required_fields(self):
        for offset, value in ((14, 0x44), (14, 0x55), (46, 0x40)):
            raw = bytearray(frame())
            raw[offset] = value
            self.assertEqual(review_bytes(pcap([bytes(raw)]))["status"], "FAIL")

    def test_multiple_records_and_messages(self):
        payload = record(hello() + hello(2)) + record(hello(grease=False))
        r = review_bytes(pcap([frame(payload)]))
        self.assertEqual(
            (r["status"], len(r["hellos"]), r["counts"]["tls_records"]), ("PASS", 3, 2)
        )

    def test_old_hello_without_extensions_and_hrr(self):
        self.assertEqual(
            review_bytes(pcap([frame(record(hello(extensions=False)))]))["hellos"][0]["tag"],
            "771,4865-4866,,,",
        )
        r = review_bytes(pcap([frame(record(hello(2, hrr=True)))]))
        self.assertEqual(r["hellos"][0]["server_variant"], "hello_retry_request")
        self.assertTrue(all(v == "OPEN" for v in r["assumptions"].values()))

    def test_duplicate_extension_and_empty_handshake_are_fail(self):
        for payload in (record(hello(duplicate=True)), record() + record(b"")):
            self.assertEqual(review_bytes(pcap([frame(payload)]))["status"], "FAIL")

    def test_invalid_hello_vectors_and_extension_owners(self):
        prefix = u16(771) + bytes(32) + b"\0"
        normal = prefix + u16(2) + u16(4865) + b"\x01\0"
        exts = [
            extension(10, b"\0\x01x"),
            extension(11, b"\0"),
            extension(43, b"\x01x"),
            extension(10, b"\0\x02\0\x1dPRIVATE"),
        ]
        bodies = [
            prefix + u16(1) + b"x" + b"\x01\0",
            prefix + u16(0) + b"\x01\0",
            prefix + u16(2) + u16(4865) + b"\0",
        ]
        bodies += [normal + u16(len(e)) + e for e in exts]
        bodies += [
            normal + b"\0\x01",
            u16(771) + bytes(32) + b"\x21" + bytes(33) + u16(2) + u16(4865) + b"\x01\0",
        ]
        for body in bodies:
            message = b"\x01" + len(body).to_bytes(3, "big") + body
            self.assertEqual(review_bytes(pcap([frame(record(message))]))["status"], "FAIL")

    def test_change_cipher_spec_stops_opaque_cipher_state(self):
        data = pcap([frame(record() + record(b"\x01", 20) + record(hello(2)))])
        r = review_bytes(data)
        self.assertEqual((r["status"], len(r["hellos"])), ("OPEN", 1))
        self.assertIn("change_cipher_spec_cipher_state_unresolved", self.codes(r))
        self.assertEqual(
            review_bytes(pcap([frame(record() + record(b"\x02", 20))]))["status"], "FAIL"
        )

    def test_partial_record_and_handshake_are_open(self):
        for payload in (b"\x16", record()[:-1], record(hello()[:-1]), record(b"\x01\0")):
            self.assertEqual(review_bytes(pcap([frame(payload)]))["status"], "OPEN")

    def test_opaque_encrypted_or_nonhello_messages(self):
        for payload in (
            record(b"PRIVATE_ENCRYPTED", 23),
            record(b"\x0b\0\0\0"),
            record(b"\x02\x28", 21),
            record(b"\xff", 21),
            b"HTTP DATA",
        ):
            self.assertEqual(review_bytes(pcap([frame(record() + payload)]))["status"], "OPEN")

    def test_pcapng_endians_minor12_and_ignored_reserved(self):
        for endian in "<>":
            for minor in (0, 2):
                self.assertEqual(review_bytes(pcapng(endian=endian, minor=minor))["status"], "PASS")
        data = section() + interface(reserved=123) + enhanced()
        self.assertEqual(review_bytes(data)["status"], "PASS")

    def test_pcapng_timestamp_resolution_offset_and_snap_zero(self):
        for resolution, denominator in ((9, 10**9), (0x8A, 1024), (0xFF, 2**127)):
            opts = option(9, bytes([resolution])) + option(14, struct.pack("<q", -2))
            r = review_bytes(section() + interface(snap=0, opts=opts) + enhanced(ticks=3))
            self.assertEqual(r["status"], "PASS")
            self.assertEqual(
                r["hellos"][0]["timestamp"],
                {"numerator": 3 - 2 * denominator, "denominator": denominator},
            )

    def test_pcapng_sections_reset_endianness_and_interfaces(self):
        part = interface() + enhanced()
        data = section(declared=len(part)) + part + pcapng(endian=">")
        r = review_bytes(data)
        self.assertEqual((r["status"], r["counts"]["sections"], len(r["hellos"])), ("PASS", 2, 2))
        self.assertEqual([x["section"] for x in r["hellos"]], [0, 1])

    def test_section_boundary_lengths(self):
        part = interface() + enhanced()
        for declared in (4, len(part) - 4, len(part) + 4, -2):
            self.assertEqual(review_bytes(section(declared=declared) + part)["status"], "FAIL")

    def test_pcapng_multiple_interfaces(self):
        data = (
            section()
            + interface(link=113)
            + interface(link=101)
            + enhanced(frame(link=101), index=1)
        )
        self.assertEqual(review_bytes(data)["hellos"][0]["interface"], 1)
        self.assertEqual(
            review_bytes(section() + interface() + enhanced(index=1))["status"], "FAIL"
        )

    def test_simple_packet_has_no_timestamp(self):
        raw = frame()
        data = (
            section()
            + interface(snap=0)
            + block(3, struct.pack("<I", len(raw)) + raw + bytes((-len(raw)) % 4))
        )
        r = review_bytes(data)
        self.assertEqual(r["status"], "OPEN")
        self.assertIsNone(r["hellos"][0]["timestamp"])

    def test_options_implicit_end_and_private_comments(self):
        data = pcapng(opts=option(2, b"PRIVATE_INTERFACE"))
        self.assertEqual(review_bytes(data)["status"], "PASS")
        self.assertNotIn(b"PRIVATE_", encode_report(review_bytes(data)))
        self.assertEqual(review_bytes(pcapng(opts=option(0, b"")))["status"], "PASS")
        opts = option(2, b"a") + option(0, b"")
        self.assertEqual(
            review_bytes(pcapng(opts=opts), limits=Limits(options=1))["status"], "PASS"
        )

    def test_unknown_block_and_option_are_open(self):
        self.assertEqual(review_bytes(pcapng() + block(0xDEADBEEF, b"PRIVATE_"))["status"], "OPEN")
        self.assertEqual(review_bytes(pcapng(opts=option(60000, b"PRIVATE_")))["status"], "OPEN")

    def test_options_padding_and_duplicate_singletons_fail(self):
        for opts in (
            option(9, b"\x06") * 2,
            option(2, b"a") * 2,
            option(9, b"xx"),
            b"\x02\0\x01\0a\x01\0\0",
        ):
            self.assertEqual(review_bytes(pcapng(opts=opts))["status"], "FAIL")

    def test_pcapng_fcs_and_dropcount_are_open(self):
        for opts in (option(2, struct.pack("<I", 1 << 5)), option(4, struct.pack("<Q", 1))):
            self.assertEqual(
                review_bytes(section() + interface() + enhanced(opts=opts))["status"], "OPEN"
            )

    def test_invalid_block_repeated_lengths(self):
        for offset in (4, len(pcapng()) - 4):
            raw = bytearray(pcapng())
            struct.pack_into("<I", raw, offset, 15)
            self.assertEqual(review_bytes(bytes(raw))["status"], "FAIL")

    def test_limits_are_lower_only_typed_and_none_only(self):
        for kwargs in (
            {"input_bytes": True},
            {"findings": 0},
            {"report_bytes": 2047},
            {"packets": 9000},
        ):
            with self.assertRaises(ValueError):
                Limits(**kwargs)
        for kwargs in ({"limits": False}, {"limits": {}}, {"any_port": 1}):
            with self.assertRaises(ValueError):
                review_bytes(pcap(), **kwargs)
        for raw in (bytearray(), memoryview(b""), "", None):
            with self.assertRaises(ValueError):
                review_bytes(raw)

    def test_resource_budgets_open_and_known_fail_is_retained(self):
        for kwargs in (
            {"packets": 1},
            {"tls_records": 1},
            {"handshakes": 1},
            {"extensions": 1},
            {"vector_entries": 1},
            {"report_bytes": 2048},
        ):
            r = review_bytes(
                pcap([frame(record(hello() + hello(2))), frame()]), limits=Limits(**kwargs)
            )
            self.assertEqual(r["status"], "OPEN")
            self.assertLessEqual(len(encode_report(r)), r["limits"]["report_bytes"])
        r = review_bytes(
            pcap([frame(record() + record(b"")), frame()]), limits=Limits(report_bytes=2048)
        )
        self.assertEqual(r["status"], "FAIL")
        self.assertTrue(any(v["status"] == "FAIL" for v in r["findings"]))

    def test_oversized_input_not_hashed_and_privacy(self):
        with patch("handshake_evidence_review.review.hashlib.sha256") as digest:
            r = review_bytes(pcap(), limits=Limits(input_bytes=1))
            self.assertIsNone(r["input"]["sha256"])
            digest.assert_not_called()
        encoded = encode_report(review_bytes(pcap()))
        for private in (b"PRIVATE_", b"10.23.17", b"12345"):
            self.assertNotIn(private, encoded)

    def test_no_file_import_process_network_effects(self):
        events = []
        active = [True]

        def guard(event, args):
            if active[0] and (
                event in ("open", "import", "exec", "subprocess.Popen", "os.system")
                or event.startswith("socket.")
            ):
                events.append(event)
                raise AssertionError(event)

        data = pcap()
        before = hashlib.sha256(data).hexdigest()
        sys.addaudithook(guard)
        try:
            self.assertEqual(review_bytes(data)["status"], "PASS")
        finally:
            active[0] = False
        self.assertEqual(events, [])
        self.assertEqual(hashlib.sha256(data).hexdigest(), before)

    def test_seeded_malformed_mutations_and_all_prefixes(self):
        rng = random.Random(0x4A4133)
        base = pcapng()
        for cut in range(len(base)):
            self.assertNotEqual(review_bytes(base[:cut])["status"], "PASS")
        for _ in range(1000):
            data = bytearray(base)
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            frozen = bytes(data)
            before = hashlib.sha256(frozen).hexdigest()
            r = review_bytes(frozen, limits=Limits(report_bytes=2048))
            json.loads(encode_report(r))
            self.assertLessEqual(len(encode_report(r)), 2048)
            self.assertEqual(hashlib.sha256(frozen).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()

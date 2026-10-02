"""Verify an actual installed consumer; no target capture is ever activated."""

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

import handshake_evidence_review


def main():
    source = Path(__file__).resolve().parents[1]
    installed = Path(handshake_evidence_review.__file__).resolve().parent
    assert installed != source / "src/handshake_evidence_review"
    assert Path(sys.prefix).resolve() in installed.parents and "site-packages" in installed.parts
    distribution = importlib.metadata.distribution("handshake-evidence-review")
    assert distribution.version == "0.1.0"
    assert distribution.metadata["Name"] == "handshake-evidence-review"
    assert distribution.metadata["Requires-Python"] == ">=3.11"
    assert distribution.metadata["License-Expression"] == "BSD-3-Clause"
    assert not distribution.requires
    assert distribution.metadata.get_payload() == (source / "README.md").read_text()
    checked = []
    for path in sorted((source / "src/handshake_evidence_review").glob("*")):
        if not path.is_file():
            continue
        actual = installed / path.name
        assert actual.read_bytes() == path.read_bytes(), path.name
        checked.append(
            {"file": path.name, "sha256": hashlib.sha256(actual.read_bytes()).hexdigest()}
        )
    license_rows = []
    for name in (
        "LICENSE",
        "NOTICE",
        "licenses/salesforce-BSD-3-Clause.txt",
        "licenses/dpkt-research-BSD.txt",
        "licenses/dpkt-research-AUTHORS.txt",
    ):
        matches = [
            entry
            for entry in distribution.files
            if str(entry).endswith(".dist-info/licenses/" + name)
        ]
        assert len(matches) == 1, name
        actual = distribution.locate_file(matches[0])
        assert actual.read_bytes() == (source / name).read_bytes(), name
        license_rows.append(
            {"file": name, "sha256": hashlib.sha256(actual.read_bytes()).hexdigest()}
        )
    shared_rows = []
    configuration = tomllib.loads((source / "pyproject.toml").read_text())
    for directory, patterns in configuration["tool"]["setuptools"]["data-files"].items():
        for pattern in patterns:
            matches = sorted(source.glob(pattern))
            assert matches, pattern
            for path in matches:
                actual = Path(sys.prefix) / directory / path.name
                assert actual.read_bytes() == path.read_bytes(), str(path.relative_to(source))
                shared_rows.append(
                    {
                        "file": str(path.relative_to(source)),
                        "sha256": hashlib.sha256(actual.read_bytes()).hexdigest(),
                    }
                )
    sys.path.insert(0, str(source / "tests"))
    from fixtures import frame, hello, option, pcap, pcapng, record

    environment = dict(os.environ, PYTHONPATH="", PYTHONDONTWRITEBYTECODE="1")
    command = Path(sys.executable).parent / "handshake-evidence-review"
    rows = []
    with tempfile.TemporaryDirectory(
        dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
    ) as directory:
        outside = Path(directory)
        target = outside / "PRIVATE_CAPTURE_名字.pcap"
        malformed = bytearray(frame())
        malformed[14] = 0x44
        cases = (
            ("classic", pcap(), [], 0, "PASS"),
            ("pcapng", pcapng(), [], 0, "PASS"),
            ("server", pcap([frame(record(hello(2)))]), [], 0, "PASS"),
            ("retry", pcap([frame(record(hello(2, hrr=True)))]), [], 0, "PASS"),
            ("bad_container", pcap()[:22], [], 1, "FAIL"),
            ("bad_ip", pcap([bytes(malformed)]), [], 1, "FAIL"),
            ("duplicate_extension", pcap([frame(record(hello(duplicate=True)))]), [], 1, "FAIL"),
            ("unknown_container", b"unknown", [], 2, "OPEN"),
            ("unknown_link", pcap(link=999), [], 2, "OPEN"),
            ("partial_record", pcap([frame(record()[:10])]), [], 2, "OPEN"),
            ("truncated_capture", pcap([frame()[:14]], original=len(frame())), [], 2, "OPEN"),
            ("unknown_option", pcapng(opts=option(60000, b"PRIVATE_ANNOTATION")), [], 2, "OPEN"),
            ("default_port_scope", pcap([frame(port=444)]), [], 2, "OPEN"),
            ("explicit_any_port", pcap([frame(port=444)]), ["--any-port"], 0, "PASS"),
        )
        for name, data, flags, expected_exit, expected_status in cases:
            target.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            for prefix in ([sys.executable, "-m", "handshake_evidence_review"], [str(command)]):
                process = subprocess.run(
                    [*prefix, str(target), *flags],
                    cwd=outside,
                    env=environment,
                    capture_output=True,
                    check=False,
                )
                assert process.returncode == expected_exit, (name, process.returncode)
                assert process.stderr == b"", (name, process.stderr)
                result = json.loads(process.stdout)
                assert result["status"] == expected_status
                assert len(process.stdout) <= result["limits"]["report_bytes"]
                assert result["input"]["sha256"] == digest
                assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
                for private in (
                    b"PRIVATE_CAPTURE",
                    b"PRIVATE_HOST",
                    b"PRIVATE_SESSION",
                    b"PRIVATE_ANNOTATION",
                    b"10.23.17",
                    b"12345",
                ):
                    assert private not in process.stdout, (name, private)
                assert all(value == "OPEN" for value in result["assumptions"].values())
                rows.append(
                    {
                        "case": name,
                        "entry": "module" if len(prefix) > 1 else "installed_script",
                        "exit": process.returncode,
                        "status": result["status"],
                    }
                )
        target.write_bytes(pcap())
        link = outside / "PRIVATE_SYMLINK"
        link.symlink_to(target)
        diagnostic_cases = (
            ([], b"invalid_arguments"),
            (["--unknown", "PRIVATE_ARGUMENT"], b"invalid_arguments"),
            (["PRIVATE_ARGUMENT", "--max-input-bytes", "not_an_integer"], b"invalid_arguments"),
            ([str(target), "--max-input-bytes", "0"], b"invalid_options"),
            ([str(target), "--max-input-bytes", "16777217"], b"invalid_options"),
            ([str(target), "--max-input-bytes", "1"], b"input_bytes_budget"),
            ([str(link)], b"input_snapshot_unavailable"),
        )
        for arguments, code in diagnostic_cases:
            process = subprocess.run(
                [str(command), *arguments],
                cwd=outside,
                env=environment,
                capture_output=True,
                check=False,
            )
            assert process.returncode == 2 and process.stdout == b""
            assert code in process.stderr
            assert b"PRIVATE_" not in process.stderr
            assert str(outside).encode() not in process.stderr
            rows.append(
                {
                    "case": "fixed_diagnostic",
                    "entry": "installed_script",
                    "exit": 2,
                    "diagnostic": code.decode("ascii"),
                }
            )
        for argument in ("--version", "--help"):
            process = subprocess.run(
                [str(command), argument],
                cwd=outside,
                env=environment,
                capture_output=True,
                check=False,
            )
            assert process.returncode == 0 and process.stderr == b""
            assert b"PRIVATE_" not in process.stdout
            rows.append({"case": argument, "entry": "installed_script", "exit": 0})
        immutable = target.read_bytes()
        assert handshake_evidence_review.review_bytes(immutable)["status"] == "PASS"
        assert target.read_bytes() == immutable
    return {
        "installed_module": str(installed),
        "python_prefix": sys.prefix,
        "runtime_files": checked,
        "metadata": {
            "name": distribution.metadata["Name"],
            "version": distribution.version,
            "license": distribution.metadata["License-Expression"],
            "runtime_dependencies": distribution.requires or [],
        },
        "license_byte_matches": license_rows,
        "shared_document_byte_matches": shared_rows,
        "cli_cases": rows,
        "cases": len(rows),
        "input_unchanged": True,
        "private_raw_values_omitted": True,
    }


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))

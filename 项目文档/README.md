> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# HandshakeEvidenceReview

New implementation author and maintainer: dhtfish98.

Inspect an explicitly supplied offline PCAP or PCAPNG snapshot and report bounded
TLS hello envelopes, original JA3/JA3S compatibility tags and their physical byte
origins. The new standard-library parser reads actual capture, link, IP, TCP, TLS
record and hello fields. It does not wrap the original parser or use DPKT at runtime.
There is no live capture, network access, sample execution, fingerprint impersonation,
traffic rewriting or intelligence-list lookup.

```sh
python -m pip install --no-index --no-deps dist/handshake_evidence_review-0.1.3-py3-none-any.whl
handshake-evidence-review /absolute/authorized/capture.pcap
handshake-evidence-review /absolute/authorized/capture.pcapng --any-port
```

```python
from handshake_evidence_review import Limits, review_bytes, encode_report
result = review_bytes(authorized_immutable_bytes, limits=Limits(), any_port=False)
print(encode_report(result).decode('ascii'), end='')
```

The default port profile inspects TCP payloads with either endpoint on port 443.
`--any-port` makes that filter broader; it is an explicit profile choice, not proof
that a port identifies TLS. The API accepts immutable `bytes`, a `Limits` instance
or `None`, and a real Boolean. Invalid API contracts raise fixed `ValueError` text.
The CLI opens only the supplied local regular file. Its POSIX reader holds ancestor
descriptors, refuses symlinks and `..`, uses no-follow/nonblocking opens, checks
identity/size/timestamps before and after reading, and rejects unsupported flags or
platforms. That consistency observation does not authenticate acquisition.

CLI stdout contains one bounded ASCII JSON report: exit 0 PASS, 1 FAIL, 2 OPEN.
Argument and snapshot errors produce a fixed diagnostic on stderr and exit 2,
without echoing a path, user argument, captured value or exception. Help/version
are fixed text. `--max-input-bytes` lowers the input limit; other lower-only typed
limits are available through the API.

PASS completes the frozen capture/envelope/fingerprint profile without a definite
format violation or coverage gap. FAIL records a definite admitted envelope or
required-field inconsistency. OPEN records incomplete capture, opaque unsupported
features or exhausted budgets. Definite FAIL survives later OPEN and report caps.
All reports separately keep capture authenticity, wire checksums, TCP flow completeness,
TLS semantics/authentication, peer identity, maliciousness/safety and CVP eligibility
OPEN. A compatibility fingerprint is neither a security verdict nor an identity.

Classic PCAP supports all four microsecond/nanosecond endian magics and version2.4.
PCAPNG supports endian-changing sections, version1.0/1.2, interface descriptions,
enhanced packets, and simple packets. Simple packets lack timestamps and stay OPEN.
Timestamps preserve integer ticks as a numerator/denominator with declared signed
offset; no floating-point conversion or authenticated clock is claimed. Unknown
blocks/options and unsupported link/fragment/reassembly features stay visible as OPEN.
Historical reserved PCAP words and the IDB reserved word are ignored as specified.

The supported link envelopes are Ethernet with at most two VLAN tags, Linux SLL/SLL2,
RAW IP, BSD NULL and network-order LOOP. Unfragmented IPv4/IPv6 TCP envelopes are
walked. IP/TCP options and IPv6 extension semantics are opaque OPEN. TCP sequence
reassembly, IP fragments (including IPv6 atomic fragments), cross-record handshake
reassembly, encryption and renegotiation state are unsupported. Multiple complete
hello messages and records are actually walked. A valid ChangeCipherSpec produces
OPEN and stops the current TCP payload before assuming later bytes are plaintext.

JA3 removes exactly the sixteen RFC8701 GREASE values from cipher, extension and
group vectors. JA3S retains original Salesforce extension-ID behavior, including
GREASE; that compatibility behavior does not validate server negotiation. TLS1.3
uses the observed legacy hello version in the tag, with offered/selected versions
as separate observed integers. HelloRetryRequest is labeled from its fixed random
value, without treating it as handshake completion. The MD5 field is explicitly
compatibility metadata, not an authenticity signature.

Default reports omit IP/MAC addresses, ports, hostnames, random/session values and
extension payload text. There is no disclosure mode or raw capture/XML dump. Hello
and body offsets, sizes and SHA-256 hashes refer to their exact physical input
ranges. Hashes are provenance, not anonymization or proof of authenticity. No target
strings become code, commands, URLs or terminal actions.

See [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>), [ORIGIN.md](<ORIGIN.md>),
[VALIDATION.md](<VALIDATION.md>) and the complete notices in [NOTICE](<NOTICE>).

Local file I/O requires the positive integer OS protection flags documented by
the reader/writer. Missing, zero, None, Boolean or non-integer flags return a
controlled OPEN/error before requested filesystem input/output instead of
weakening the boundary. Native
Windows file I/O is not verified; the current verification is macOS POSIX.

Directory descriptor capability contract: `os.supports_dir_fd` must be a set or frozenset containing `os.open` before requested local file access. Missing, malformed or incomplete capability declarations return the existing controlled OPEN/error result. This finite POSIX contract is checked locally; native Windows file operations are not implemented or claimed.

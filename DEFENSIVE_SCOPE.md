# Frozen format and evidence contract

This project independently implements the complete finite offline workflow below,
informed by the selected Salesforce JA3 scripts. It does not claim a complete TLS
implementation or equivalence with every upstream capture/Zeek feature.

| Layer | Measured profile and boundary |
|---|---|
| Input | Immutable bytes, at most16MiB; no hashing of over-cap unadmitted input. One explicit local regular-file snapshot for CLI. No archives, URLs, stdin sniffing or live collection. |
| PCAP | Four endian/time magics, v2.4, nonzero snaplen, all packet lengths and exact physical bounds, fractional-time ranges. Captured<original is OPEN truncation; captured>original is historical OPEN, not a universal corruption assertion. Additional high link-information bits remain OPEN. |
| PCAPNG | SHB repeated lengths/alignment/order, versions1.0/1.2, explicit section-end boundaries and endian changes, reset per-section IDBs, EPB interface IDs/ticks/packet padding/options, SPB implicit interface0 and snap bounds. Unknown block types remain OPEN. No secret/compression/name-resolution block interpretation. |
| Options | Complete owner-relative TLV/padding/bounds, permitted absent end-of-options, singleton checks for known SHB/IDB/EPB options, fixed sizes and finite hash/verdict type sizes. Private annotations are discarded. Hash/verdict/FCS/error/offload meanings and unknown options remain OPEN. No BPF/eBPF program loading or resource lookup. |
| Time | Exact observed integer numerator/denominator for default10^-6, binary/decimal tsresol exponent0..127 and signed second offset. SPB time absent OPEN. Capture-clock accuracy and timezone/acquisition authenticity remain OPEN. |
| Link | Ethernet with zero/two VLAN tags, SLL16, SLL2 20, RAW101, NULL0 with capture-endian BSD families2/24/28/30, LOOP108 with network-endian family. Other namespaces/link types OPEN. |
| Network | Bounded IPv4 total/IHL and IPv6 payload headers, TCP data-offset boundaries; no address output. IPv4/IPv6 fragments, jumbograms/protected payloads OPEN; up to8 IPv6 option/routing envelope headers are bounded but their semantics OPEN. IP/TCP checksums are not verified; wire integrity permanently OPEN. |
| TLS | Plaintext-envelope hypothesis for record headers and multiple complete handshake envelopes; complete ClientHello/ServerHello version/random/session/cipher/compression/extensions. Duplicate extension IDs, malformed vector lengths and required field bounds FAIL. Supported groups/point formats/versions vectors are actually decoded; other extension payload semantics are outside this profile. No certificate/authentication/protocol-policy verdict. |
| State | Incomplete records/messages or unrecognized TCP payload OPEN. No cross-packet or cross-record reassembly. Valid CCS means cipher state unresolved OPEN and stops the current payload. Other encrypted/application/non-hello messages remain opaque OPEN. Every reported hello is an unauthenticated envelope hypothesis. |
| Fingerprint | Original JA3 decimal segments and exact GREASE filtering; original JA3S decimal version/selected cipher/extension IDs, including original unfiltered GREASE IDs. MD5 compatibility tag only. HRR marker and supported_versions are observations, not negotiation proof. |
| Provenance | Whole admitted input SHA; exact packet/record/hello/body physical positions. Complete hello/body SHA values match their reported ranges. Unknown format regions produce bounded reason/position findings rather than a clean absence conclusion. |

Limits only decrease:16MiB input,8192 packets,16384 PCAPNG blocks,64 sections,
64 interfaces per section,262144 bytes per packet,16384 TLS records,4096 handshake
messages,512 extensions per hello,2048 vector entries,256 nonterminal options per
block,512 findings and1MiB final JSON including newline. Report budgets must allow
at least2048 bytes. A cap is OPEN; known FAIL is retained. Output has an incremental
hello-content charge and a final total-JSON check, with a bounded fallback summary.

Defensive use is reviewing authorized offline traffic evidence and correlating
observed tags with independently acquired context. This repository supplies no
scanner, collector, evasion generator, packet transmission, command execution,
traffic alteration, malware attribution or intelligence updater. It does not infer
that equal fingerprints imply equal software, equal users, trust or maliciousness.
It does not manufacture model safeguards events, applicant identity, organization
membership or CVP acceptance evidence.

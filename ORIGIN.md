# Fixed source and authorship

The selected reference is [salesforce/ja3](https://github.com/salesforce/ja3/tree/502cc6395811c54743b0561419d61900a6df3ff7),
fixed at `502cc6395811c54743b0561419d61900a6df3ff7` under BSD-3-Clause. All three
selected Python runtime scripts (756 lines), package initializer, setup, requirements,
root/Python READMEs and complete original license were read in full:9 files,1003
physical lines. Their SHA-256 and fixed Git blob identities are recorded in
`evidence/scope-gate.json`. This does not claim an audit of the entire archived
repository, Zeek code, intelligence lists or upstream dependency implementations.
The original Salesforce copyright and complete license remain verbatim in
`licenses/salesforce-BSD-3-Clause.txt`.

The new cursor, capture, network, TLS, budget, evidence and CLI implementation is
independent Codex-assisted code for bitfish886. It uses standard-library parsing
and does not call or redistribute the original runtime. The applicant is not
represented as sole original author of the upstream project. Salesforce's old raw
IP/port/packet reporting and threat implications are not adopted. Multiple hello
walking and explicit OPEN gaps replace silent skips. The held-descriptor snapshot
mechanism follows the shared defensive reader pattern used in this new30 batch;
its runtime source is independently written and reviewed here.

Research-only primary format readings were:

- IETF draft-ietf-opsawg-pcap-09, complete technical lines179..430, covering global/packet format and historical reserved/original-length cases.
- IETF draft-ietf-opsawg-pcapng-06, complete selected lines199..627 and709..1868, covering sections/interfaces/packet blocks/options; custom option vendor semantics are excluded.
- RFC8446 selected complete technical lines1485..2216 and4326..4434 for hello/extensions/versions and record envelopes; RFC8701 lines82..306 for all GREASE values and rules.
- RFC791 lines831..1069, RFC8200 lines297..433,567..668,735..958 and RFC9293 lines277..520 for bounded IP/TCP envelope facts.
- tcpdump `4a789712f187e3ac7b2c0044c3a3f8c71b83646e`, entire print-null.c/af.h and print-sll.c lines1..180 for capture family/SLL layouts. These C implementations and specification text are not copied into runtime or redistributed.

Full primary-document hashes and selected-scope identities accompany the final
engineering evidence. Historical draft-08 PCAP magic typographical inconsistencies
were not adopted; the newer pinned draft-09 and actual four-magic controls are used.
Reading selected format facts does not imply a complete standard-library, packet
stack or TLS implementation audit.

Actual comparison ran all three unchanged fixed Salesforce scripts with pinned
research-only DPKT1.9.8 and setuptools80.9.0 on synthetic benign complete captures.
The original requirement names DPKT1.9.1; the research version is explicitly newer,
and no DPKT implementation is bundled as product runtime. Its complete metadata,
BSD license and authors notice were read; whole dependency implementation remains
OPEN. No real user traffic or raw original research output is redistributed.

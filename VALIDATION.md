# Validation evidence and limits

The initial local source suite has40 methods on Python3.14.6, with an independent
benign binary writer. It covers exact JA3/JA3S formulae/GREASE behavior, legacy versus
supported versions, HRR, complete hello/body source ranges/hashes, four classic
magic variants, PCAPNG endians/sections/interfaces/options/snap/tick resolution,
all six link types with IPv4/IPv6, multiple messages/records, valid CCS uncertainty,
truncations, malformed owners/vectors, unknown features, privacy and bounded output.
Secure snapshot tests exercise real leaf/ancestor symlinks, FIFO/nonregular input,
changed descriptor metadata, every absent required flag and missing dir_fd support.

The suite executes1000 fixed-seed malformed PCAPNG mutations and every strict
prefix of a benign fixture. An actual API audit-hook control rejects file/import/
process/socket execution attempts; no attempt occurs and input bytes are unchanged.
Over-cap input is checked with digest instrumentation and makes zero SHA calls.
These are bounded measured paths, not exhaustive fuzzing or a safety proof.

A separately written parent harness has76 pre-freeze independent structure/profile
controls, including byte-level PCAPNG option errors, legitimate capture truncation,
hello hashes, exact binary timestamp denominators/offsets and mixed section bounds.
It found and verified fixes for mismatched hello-range hashes, zero-length handshake
records, unknown SHB options, incomplete singleton/option-size checks, legitimate
truncation misclassification and known-failure retention at report caps. Its final
installed-package results are recorded externally; source pre-review alone does
not establish a package or remote CI result.

`evidence/upstream-differential.json` records an actual unchanged fixed-upstream
comparison:36 generated capture/module comparisons and72 tag/MD5 comparisons,
zero differences. Each of the three original scripts is exercised with both
GREASE choices, both capture endians, classic micro/nanosecond and PCAPNG inputs.
The input profile is complete single-hello benign data, not arbitrary TLS semantics,
flow reassembly, malformed-parser equivalence or a real-world capture corpus.

Fresh consumer checks must actually import the built wheel outside the source tree,
match all installed runtime source bytes/metadata, run the suite, and exercise
installed CLI PASS/FAIL/OPEN/privacy/argument/budget paths. Final source/wheel/sdist/
installed and complete license identities are bound in external engineering evidence.
Build tools are separately pinned by archive SHA; their metadata/licenses are
reviewed but whole implementations are not claimed audited. Runtime dependencies
are empty. CI/publication/release success requires observation for the exact commit,
not a checked-in workflow or local build.

Capture authenticity, complete TCP state, wire checksums, TLS authentication,
fingerprint identity/malice, applicant organization/model/channel and CVP approval
remain OPEN. MD5 is a historical correlation format only. Target traffic is never
executed, replayed, uploaded or collected live.

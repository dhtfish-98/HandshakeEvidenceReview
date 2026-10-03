## Current version 0.1.1: attribution and bounded verification, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.1`.

Required local reader/writer protection flags now require positive non-Boolean integers. Missing, zero, None, Boolean, string and floating-point values yield controlled OPEN/error before requested filesystem input/output. Existing fixed-source provenance and parser/generation scope are retained.

The current source suite passes 43 tests on Python 3.14/macOS arm64. Final wheel and sdist are built from the final files. A fresh consumer installation also passes 43 tests. Installed/source/wheel runtime bytes, licenses, retained upstream notices, RECORD and command contracts are verified separately before publication. Exact package hashes and execution receipts are recorded externally rather than embedded in this self-referential document.

These tests verify the documented finite profile. Historical native/reference measurements below are preserved; they are not new runs for this revision. Matching remote CI, actual deployments, applicant identity and CVP approval remain OPEN until separately evidenced.

The current directory-relative file contract also requires `os.supports_dir_fd` to be a set or frozenset containing the actual `os.open`. Missing, None, malformed and incomplete declarations yield the existing controlled OPEN/error before requested filesystem I/O. The same current suite covers these API and real installed CLI contrasts, including normal frozenset capability declarations. Trusted CLI and standard-library imports are warmed before simulated capability mutation; this test isolates the application gate rather than a damaged standard-library import. Source archive offline rebuilding and another fresh consumer verify the same suite and all uncompressed wheel payload bytes.

## Prior verification evidence

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

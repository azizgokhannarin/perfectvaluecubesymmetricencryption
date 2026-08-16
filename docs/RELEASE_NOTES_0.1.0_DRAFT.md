# PVC-RotSymEnc-1 v0.1.0-draft Release Notes

This is the first public umbrella-profile draft for the Perfect Value Cube symmetric-encryption line.

## Public review snapshot

`v0.1.0-draft-review.1` freezes the first independent human-review baseline.
It adds review navigation and reporting surfaces only; the construction,
public API, and canonical vectors remain those of `0.1.0-draft`. See
`PUBLIC_REVIEW.md` for the requested attacks, known findings, reproduction
path, and explicit non-claims.

## Cryptographic status

No new cryptographic construction was introduced. PVC-RotSymEnc-1 is defined to be byte-exactly equivalent to frozen PVC-AEAD-0 Candidate A1 / v0.2.0, which in turn pins Candidate M1 / v0.2.0 and Candidate C1 / v0.9.0.

## Added in this draft

- public algorithm name `PVC-RotSymEnc-1`;
- thin C++20 API and CLI;
- normative public-profile specification;
- cryptanalysis challenge and explicit non-claims;
- component provenance and freeze policy;
- retained Candidate A1 KAT and 4,096-case differential corpora;
- RotSymEnc-specific machine-readable vectors;
- wrapper-to-A1 deterministic equivalence test;
- coverage-guided differential fuzzing for `seal` and `open` behavior;
- GCC/Clang and separate ASan/UBSan/MSan verification;
- explicit `-O0`, `-O2` and `-O3` conformance builds;
- CBMC bounded verification of framing, length, counter, tag-gate, and
  verify-before-decrypt invariants;
- dedicated bounded StreamFrame-domain differential, Walsh, collision, and
  cross-role analysis;
- opt-in x86 dudect timing characterization with retained raw measurements;
- fixed-fingerprint cross-platform conformance on Linux x86-64, Linux ARM64,
  macOS ARM64, and Windows x64 with GCC, Clang, Apple Clang, MSVC, and clang-cl;
- opt-in nonce-management and misuse analysis with analysis-only detector and
  persistent-counter prototypes;
- opt-in software fault-injection analysis covering canonical data faults,
  finalization-adjacent C1 state faults, and explicit control-flow models;
- opt-in 0 B-1 MiB seal/open performance characterization with retained raw
  samples, TSC ticks, corrected resident-memory measurements, and external
  system-library controls;
- a fail-closed one-command reproducibility campaign with per-stage logs and
  artifact hashes;
- GitHub Actions CI.

## Local verification summary

```text
GCC Release CTest:              6/6
Clang Release CTest:            6/6
ASan CTest:                     6/6
UBSan CTest:                    6/6
MSan CTest:                     6/6
Clang -O0/-O2/-O3 CTest:      18/18
Release A1 equivalence:      4096/4096 (GCC)
Release A1 equivalence:      4096/4096 (Clang)
Sanitizer equivalence:       1536/1536
Official RotSymEnc vectors:      5/5
Wrapper/A1 mismatches:             0
CBMC selected properties:       passed (bounded; see BOUNDED_VERIFICATION.md)
StreamFrame-domain campaign:    no distinguisher found at tested bounds
Timing characterization:        secret-key-dependent C1 timing observed
Cross-platform transcript:      4096/4096, 6 toolchain/platform combinations
Cross-platform mismatches:      0
Performance cases:              96/96 primary, plus targeted replication
Large-payload throughput:       about 0.066 MiB/s GCC, 0.089 MiB/s Clang
Nonce management profiles:      4/4; 2 expected known misuse findings
Nonce campaign CI:              4/4 profiles; full run 23/23 jobs
Fault injection profiles:       4/4; canonical altered-tuple acceptances 0
Fault replication:              101376 state faults; 35 distance-one candidates
Fault campaign CI:              4/4 profiles; full run 27/27 jobs
Fault finalization diagnosis:   297984 state faults plus stepwise traces
Fault diagnosis mirror:         101376 entry; 7858 canonical/faulted checks
One-command reproduction:       local 9/9 stages; CI 19/19 jobs
```

The conformance evidence establishes reproducibility of the public wrapper in
the tested environments. The bounded negative cryptanalysis does not establish
cryptographic security. The timing campaign found an implementation-side
weakness; it did not demonstrate key recovery, forgery, or a remote attack.
The cross-platform campaign found no byte-output divergence at the tested
bounds; this does not establish portability outside the recorded matrix.
The performance figures characterize one reference implementation and host;
they are not security properties or cross-machine guarantees.
The nonce campaign reproduced the specified reuse disclosure and showed that
snapshot rollback defeats a standalone persistent counter; the tested helper
prototype is not a supported API or a misuse-resistance claim.
The software fault campaign found recurrent silent C1 prefixes and
distance-one tag candidates at one late injection boundary. It did not
demonstrate physical fault feasibility, practical forgery, or key recovery.
The diagnostic follow-up attributed much of the final-byte concentration to
profile truncation plus dynamic squeeze reachability; it found no fixed
all-case coordinate and made no normal-input security claim.

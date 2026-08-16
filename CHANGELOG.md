# Changelog

## Public review snapshot 1 - 2026-08-17

- Froze `v0.1.0-draft-review.1` as the first independent human-review baseline.
- Added a concise public review request and structured finding-report form.
- Consolidated the reviewer entry path, known findings, non-claims, and
  reproducibility instructions without changing construction bytes, public API,
  or canonical vectors.

## 0.1.0-draft

- Introduced public algorithm name `PVC-RotSymEnc-1`.
- Defined normative byte-equivalence to PVC-AEAD-0 Candidate A1 / v0.2.0.
- Added a thin C++20 API and CLI.
- Vendored the frozen Candidate A1 dependency tree without cryptographic modification.
- Retained Candidate A1 KAT and independent differential corpora.
- Added security target, provenance, freeze policy, review workflow and cryptanalysis challenge.
- Added wrapper-to-A1 conformance and equivalence tests.
- Added opt-in Clang libFuzzer differential targets for valid `seal` tuples and
  arbitrary or malformed `open` tuples, with ASan/UBSan instrumentation,
  deterministic seed corpora and CI smoke coverage.
- Added opt-in whole-tree ASan, UBSan and MSan CMake profiles, including MSan
  origin tracking, plus explicit `-O0`, `-O2` and `-O3` CI conformance jobs.
- Added a reproducible MSan/`libstdc++` boundary control and documented the
  instrumented-standard-library limitation without changing the construction.
- Added CBMC bounded implementation verification, StreamFrame-domain analysis,
  timing characterization, cross-platform conformance, performance
  characterization, a one-command reproduction campaign, nonce-misuse
  analysis, and software fault-injection diagnostics.
- Retained explicit positive findings and bounded negative campaigns in the
  attack log and versioned result artifacts. See
  `docs/RELEASE_NOTES_0.1.0_DRAFT.md` for the complete measured summary and
  limitations.

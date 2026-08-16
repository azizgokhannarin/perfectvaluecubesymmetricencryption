# Changelog

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

# Trust Path Roadmap

## Stage R0 — draft umbrella profile

- public `PVC-RotSymEnc-1` name;
- normative byte-equivalence to Candidate A1;
- thin C++ API and CLI;
- retained A1 vectors and manifests;
- wrapper/A1 equivalence tests;
- explicit security targets and non-claims.

## Stage R1 — portability and conformance

- GCC/Clang/sanitizer reproducibility;
- Windows/MSVC or additional compiler verification;
- independent consumer implementation of the public profile;
- machine-readable official RotSymEnc vectors;
- package-level provenance verification.

## Stage R2 — public review candidate

- freeze a `v1.0.0-rc1` public profile if no byte ambiguity is found;
- publish consolidated cryptanalysis map;
- publish paper/ePrint material linking C1, M1, A1 and RotSymEnc;
- solicit external cryptanalysis and independent implementations.

## Stage R3 — external evidence

Only external review can move confidence beyond the current designer/AI bounded-test state. Production or standards claims require substantially more evidence and are outside the present project status.

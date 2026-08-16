# PVC-RotSymEnc-1 v0.1.0-draft Release Notes

This is the first public umbrella-profile draft for the Perfect Value Cube symmetric-encryption line.

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
- GCC/Clang/ASan+UBSan verification;
- GitHub Actions CI.

## Local verification summary

```text
GCC Release CTest:              6/6
Clang Release CTest:            6/6
ASan + UBSan CTest:             6/6
Release A1 equivalence:      4096/4096 (GCC)
Release A1 equivalence:      4096/4096 (Clang)
Sanitizer equivalence:        256/256
Official RotSymEnc vectors:      5/5
Wrapper/A1 mismatches:             0
```

This evidence establishes reproducibility of the public wrapper in the tested environments. It does not establish cryptographic security.

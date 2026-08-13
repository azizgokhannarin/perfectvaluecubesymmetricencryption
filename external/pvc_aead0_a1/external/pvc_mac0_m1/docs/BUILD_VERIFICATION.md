# PVC-MAC-0 Candidate M1 / v0.2.0 Build Verification

Verified from the Candidate M1 source tree on 2026-08-02.

```text
GCC 14.2.0 Release:              26/26
Clang 17.0.0 Release:            26/26
GCC ASan + UBSan:                26/26
GCC warnings:                    0
Clang warnings:                  0
```

The Release test configurations use the complete 4,096-case differential budget. The sanitizer configuration uses the same 26 test entries with `PVCMAC0_DIFFERENTIAL_CASES=256`; this lower budget is explicit because two sanitized C1 evaluations per differential case are substantially slower. The full 4,096-case corpus remains Release-verified with both GCC and Clang.

Sanitizer configuration:

```text
-fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_OPTIONS=detect_leaks=1
UBSAN_OPTIONS=print_stacktrace=1
PVCMAC0_DIFFERENTIAL_CASES=256
```

## Candidate M1 closure results

```text
Canonical KAT corpus:                  48/48
Independent KAT corpus:                48/48
GCC differential cases:               4096/4096
Clang differential cases:             4096/4096
Sanitizer differential cases:          256/256
Frame mismatches:                      0
Full 256-bit C1 output mismatches:     0
Truncated-tag mismatches:              0
Valid cross-implementation rejects:    0
Modified-tag accepts:                  0
Bounded integration/API misuse audit:  passed
```

## Reproducibility and preservation

```text
Vendored C1 manifest:          all files OK
C1 zero-key / abc vector:      matched
48-vector regeneration:        byte-identical
4096-vector regeneration:      byte-identical
Framing audit:                 789507 frames, 0 collisions
Message-bit avalanche:         avg 127.879, min 108, max 147
src/mac.cpp vs v0.1.1:          byte-identical
vendored C1 tree vs v0.1.1:    byte-identical
48-vector corpus vs v0.1.1:    byte-identical
```

## Candidate fingerprints

```text
SPECIFICATION.md
167a11cbeb5ef802a8ba66d4d82c9053460c9610c1b2e64f14b03f253dc5caa6

canonical src/mac.cpp
a8e5889144780c4ab1f4636239387e4a3bb3be003fecbe3126cfe08c598891cb

independent wrapper src/mac.cpp
d9482069dffd5fe4b1787569420585f7f2af4bd01f3883a2c9f4d0a6dd6158c8

48-vector KAT corpus
482b36274d940c1279a69b47c9254bbcfb1fb1c821c2dfacce39441fb9cca1ea

4096-case differential corpus
941fddaf40f82bcf7929d7be1a9f396676bd75b1e7496e9c2594e6aa408078d6

vendored C1 manifest
6321a101516bea1766e8192ab64df62431dbaa667115ee9697f14c66c952aeb2
```

Raw logs are retained under `results-0.2.0/`.

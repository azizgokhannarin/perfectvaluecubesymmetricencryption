# One-Command Reproduction Result

## Question

Can the pre-registered PVC-RotSymEnc-1 assurance package be reproduced through
one fail-closed command from a clean tree?

## Method

Commit `930ecdd4d945883a1ad97839f3361afa6acad84c` was tested with the default
`./reproduce_all.sh` profile. Every stage wrote a separate log. The campaign
ran source/nested manifests before and after executable checks and produced an
artifact hash manifest. The local managed runner used
`ASAN_OPTIONS=detect_leaks=0` for its documented `ptrace` restriction; GitHub
Actions retained default leak detection.

## Parameters

- Host: local Linux x86-64, Intel Core i7-10710U
- Main compiler: GCC 14.2.0
- Fuzz compiler: Clang 19.1.7
- CBMC: 6.10.0
- Release equivalence corpus: 4,096 cases
- Fuzz seed smoke: 256 runs per target, seed 1, maximum length 4,096 bytes
- StreamFrame campaign: 4,096 samples, two 12-variable Walsh trials, seed
  `0x53545245414D4631`
- Performance reproduction: 18 cases, three samples, 10 ms target batch

## Result

- All nine staged checks and artifact-manifest generation passed.
- Release CTest passed 6/6.
- Five KAT vectors and 4,096 differential cases passed with no mismatch.
- The 4,096-case cross-platform transcript matched its retained 2,533,365-byte
  SHA-256 fingerprint.
- Both fuzz seed campaigns passed with no mismatch or ASan/UBSan finding.
- All four CBMC harnesses reported `VERIFICATION SUCCESSFUL`.
- The StreamFrame campaign reported `alarm_count=0` at its registered bounds.
- All 18 benchmark cases completed and successful opens returned the prepared
  plaintext. The 4 KiB rows measured 0.065376-0.066225 MiB/s on this run.
- Both manifest passes and the retained artifact hashes matched.
- GitHub Actions run `31967427920` passed all 19 jobs, including the same
  one-command campaign with default leak detection.

## Interpretation

The result supports reproducibility of the assembled assurance workflow in the
two recorded GNU/Linux environments. It found no new implementation mismatch
or construction defect. This is not a security proof and does not override the
known nonce-reuse weakness or the observed C1 timing leakage.

## Limitations

The constituent campaign limits remain applicable. In particular, fuzzing and
StreamFrame analysis are bounded, CBMC uses verification models, the local
LeakSanitizer result is unavailable, hosted cross-platform evidence is external
to the local command, and performance measurements are host-specific.

## Reproduction

```bash
ASAN_OPTIONS=detect_leaks=0 \
CBMC=/tmp/cbmc-6.10.0/usr/bin/cbmc \
./reproduce_all.sh

(cd results-0.1.0-draft/reproduction/LOCAL_2026-08-16 && \
  sha256sum --quiet -c ARTIFACTS.SHA256)
```

The first command records the local sanitizer exception in `SUMMARY.txt`.
Do not disable leak detection on a runner that supports LeakSanitizer.

# Reproducibility Campaign

## Status

This document pre-registers the first one-command campaign. The campaign result
is pending. The script changes assurance and packaging only; the candidate
construction and canonical vectors are unchanged.

## Question

Can an independent reviewer invoke one command from a clean checkout and
reproduce the retained build, known-answer, differential, fuzz-seed, bounded
verification, StreamFrame-domain, performance, and manifest checks?

## Method

`./reproduce_all.sh` runs each surface as a separate fail-closed stage and
writes a stage log, a key-value summary, structured performance output, CBMC
logs, and SHA-256 hashes for the retained campaign artifacts. It never silently
skips a missing compiler, Python, CMake, Git, SHA-256 implementation, or CBMC.

The default performance stage is a short 18-case reproducibility measurement:
0, 64, and 4,096-byte payloads, all three tag profiles, both operations, three
samples, and a 10 ms target batch. `--full-performance` selects the complete
pre-registered 48-case performance matrix instead. Neither mode defines a
performance pass threshold.

The default command requires a clean tracked worktree. `--allow-dirty` exists
for harness development, records the dirty state, and is not valid release
evidence. The output directory must not already exist, preventing an earlier
campaign from being silently mixed into a new result.

## Parameters

The campaign fixes these deterministic subcampaign parameters:

- Release CTest with 4,096 wrapper/A1 equivalence cases;
- five official RotSymEnc known-answer vectors;
- the 4,096-case local cross-platform transcript fingerprint;
- two libFuzzer seed-corpus campaigns, seed 1, 256 runs, 4,096-byte maximum;
- CBMC 6.10.0 using the bounds in `docs/BOUNDED_VERIFICATION.md`;
- StreamFrame audit seed `0x53545245414D4631`, 4,096 samples, two 12-variable
  Walsh trials;
- the default 18-case performance measurement described above;
- source, profile, dependency, and nested Candidate A1 manifests before and
  after executable tests.

## Acceptance Criteria

- every required dependency is present before substantive work begins;
- every stage exits successfully, with no skipped stage;
- KAT, differential, fuzz, conformance, CBMC, and StreamFrame checks pass at
  their recorded bounds;
- successful benchmark opens return the prepared plaintext;
- both manifest passes match;
- the summary reports `status=passed` and artifact hashes are produced;
- construction sources and canonical vectors remain unchanged.

## Result

Pending the first clean-tree campaign.

## Interpretation

A passing campaign will establish that the documented local assurance package
can be executed through one fail-closed entry point in the recorded environment.
It will not establish cryptographic security or eliminate the individual
limitations of any constituent experiment.

## Limitations

- The complete local entry point currently targets GNU/Linux: it uses the
  pinned Linux CBMC package, GNU `sha256sum`, Clang libFuzzer, and the benchmark's
  Linux resident-memory measurement.
- Hosted cross-platform jobs remain CI evidence; one local command cannot
  reproduce Windows, macOS, Linux ARM64, and Linux x86-64 simultaneously.
- The fuzz stage is a deterministic seed smoke campaign, not an exhaustive or
  long-duration fuzzing claim.
- CBMC remains bounded and model-dependent.
- StreamFrame analysis is a bounded statistical/structural campaign.
- Performance output is host-specific. The default short profile is not a
  replacement for the retained primary performance campaign.
- A one-command wrapper can make evidence easier to reproduce; it cannot turn
  empirical results into a security proof.

## Reproduction

Install CBMC 6.10.0 and provide its executable when it is not on `PATH`:

```bash
CBMC=/path/to/cbmc ./reproduce_all.sh
```

To retain the full performance matrix in the same campaign:

```bash
CBMC=/path/to/cbmc ./reproduce_all.sh \
  --output build-reproduce-all-full --full-performance
```

Under a runner where LeakSanitizer cannot initialize because of an externally
verified `ptrace` restriction, the fuzz stage may be run with
`ASAN_OPTIONS=detect_leaks=0`. That limitation is recorded in `SUMMARY.txt`;
ASan and UBSan remain enabled, and CI retains its default leak check.

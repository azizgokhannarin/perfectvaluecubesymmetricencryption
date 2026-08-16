# Reproducibility Campaign

## Status

The one-command campaign was pre-registered in commit
`930ecdd4d945883a1ad97839f3361afa6acad84c` and then executed from that clean
tree locally and in GitHub Actions. The script changes assurance and packaging
only; the candidate construction and canonical vectors are unchanged.

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

The local GNU/Linux campaign completed all stages in 4 minutes 7 seconds:

| Stage | Recorded result |
|---|---|
| dependency preflight | CMake 3.31.6, Python 3.13.5, GCC 14.2, Clang 19.1.7, CBMC 6.10.0 |
| manifests before | source, profile, dependency, and nested Candidate A1 passed |
| Release tests | 6/6, including 4,096 equivalence cases |
| KAT/differential | 5/5 KAT, 4,096/4,096 differential, zero mismatch |
| conformance fingerprint | 4,096 cases, 2,533,365 bytes, fixed SHA-256 matched |
| fuzz seeds | 2/2 deterministic libFuzzer campaigns passed |
| CBMC | frames, seal lengths, open control flow, and counter domain passed |
| StreamFrame domain | `alarm_count=0` at the registered bounds |
| performance | 18/18 cases; successful-open plaintext checks passed |
| manifests after | all retained manifests passed again |
| artifact integrity | every file in `ARTIFACTS.SHA256` matched |

The local runner used `ASAN_OPTIONS=detect_leaks=0` because LeakSanitizer cannot
initialize under its independently reproduced `ptrace` restriction. ASan and
UBSan remained active. GitHub Actions run `31967427920` completed all 19 jobs,
including the new `reproduce-all` job with default leak detection.

The complete retained local evidence is under:

```text
results-0.1.0-draft/reproduction/LOCAL_2026-08-16/
```

## Interpretation

The result establishes that the documented local assurance package executed
through one fail-closed entry point in both recorded GNU/Linux environments.
It does not establish cryptographic security or eliminate the individual
limitations of any constituent experiment. No new construction defect or
implementation disagreement was observed in this campaign.

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

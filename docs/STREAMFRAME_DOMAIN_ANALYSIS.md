# StreamFrame-Domain Cryptanalysis

## Status

This document pre-registers a bounded campaign against the real Candidate A1
`StreamFrame` distribution. PVC-RotSymEnc-1 remains experimental research
software. The campaign does not modify the construction or canonical vectors.

## Question

Does frozen C1 exhibit an immediately visible collision, differential bias, or
restricted affine component when evaluated on structured, valid A1
`StreamFrame(N, i, t)` inputs?

The tested relations are:

- same key, nonce, and tag profile with counters `i` and `i + 1`;
- same key, counter, and tag profile with a single nonce-bit difference;
- valid 59-bit counters with Hamming weights 1 and 58;
- the 128/192/256 tag-profile frame relations;
- same-key outputs across eight nonces and sequential counters;
- exact Walsh spectra on nonce, counter, and mixed affine subspaces.

## Method

`analysis/streamframe_domain_audit.cpp` calls the canonical A1
`frame_stream_block` function and frozen C1
`research_keyed_return_output_a2` directly. It does not copy or alter either
construction.

Differential records include output Hamming distance, equal 16/24/32/64-bit
prefixes, full equality, and the largest per-output-bit flip-rate z-score.
The multi-query census records full 256-bit collisions, per-bit one rates, and
byte-frequency chi-square. Each is printed beside a deterministic SplitMix64
random-output control. SplitMix64 is used only to generate experiment inputs
and controls; it is not part of PVC-RotSymEnc-1.

The Walsh stage enumerates every point of three restricted affine subspaces and
uses an exact fast Walsh-Hadamard transform for each of the 256 output bits:

| Stratum | Tag profile | Active input bits |
|---|---:|---|
| nonce-spread | 128 | evenly spaced nonce bits |
| counter-low | 192 | low counter bits |
| mixed | 256 | half nonce, half low counter bits |

## Parameters

The primary campaign is fixed before result inspection:

```text
seed = 0x53545245414D4631
differential/census samples = 4096
tag profiles = 128, 192, 256 bits
counters per nonce in sequential scans = 1024
census nonces = 8
Walsh variables = 12 (4096 exact points)
Walsh trials per stratum = 2
compiler/build = GCC and Clang, Release
```

The definite alarm conditions are any full 256-bit equality between distinct
related inputs, any full collision in a census/subspace, or any affine output
bit on a tested Walsh subspace. Z-scores, prefix matches, chi-square values, and
candidate/control gaps are descriptive triage signals, not automatic claims.
A repeated absolute z-score above 6 would motivate a separately seeded
follow-up campaign; it is not by itself a break.

## Result

The primary seed completed under GCC 14.2.0 and Clang 19.1.7. After removing
the compiler-identification line, their complete result files were identical.
The primary campaign made 122,880 candidate C1 evaluations:

- 49,152 related-input pairs across 12 relation/profile strata;
- 12,288 same-key census outputs across eight nonces and three tag profiles;
- six exact 4,096-point Walsh subspaces, yielding 1,536 output-bit spectra.

No related pair produced an equal 256-bit output or equal candidate prefix at
16, 24, 32, or 64 bits. Candidate mean output Hamming distances ranged from
127.679688 to 128.372314. The largest candidate per-bit absolute z-score was
3.4375.

The census contained 12,288 distinct outputs and no within-profile or
cross-profile full collision. Across profiles, observed per-bit one rates
ranged from 0.477295 to 0.522461. Candidate byte-frequency chi-square values
were 273.371094 to 305.023438; their single deterministic controls were
241.835938 to 268.199219.

No Walsh subspace contained an output collision or affine output bit. Candidate
mean maximum correlations were 242.691406 to 244.042969, compared with
243.417969 to 245.398438 for the controls. Candidate global maxima exceeded
the control maxima by 14, 20, and 20 in the three primary strata. Because all
three differences pointed in the same direction, an exploratory full
replication used seed `0x53545245414D4632`. Its corresponding differences were
2, -4, and -8, so the direction did not reproduce. The replication also had no
defined alarm and its largest candidate absolute z-score was 3.96875.

The primary and exploratory raw records are retained under
`results-0.1.0-draft/streamframe-domain/`.

Both Release builds and the normal six-test suite passed with warnings treated
as errors. An UndefinedBehaviorSanitizer smoke campaign completed without a
finding. The AddressSanitizer smoke campaign completed without an address
error with leak detection disabled; local LeakSanitizer could not start under
the execution environment's `ptrace` constraint. This environment limitation
does not turn the smoke run into a leak check.

## Interpretation

No pre-registered definite event was observed, and the only exploratory Walsh
direction selected for replication did not persist. This campaign therefore
found no distinguisher or collision at the tested bounds. It provides evidence
against the specific tested relations and restricted affine-subspace
hypotheses only.

## Limitations

- The campaign covers finitely many keys, nonces, counters, and affine
  subspaces.
- The deterministic structured samples are not independent Bernoulli trials;
  reported z-scores and chi-square values are heuristic comparisons.
- The random controls are deterministic pseudo-random controls, not proofs of
  an ideal-function distribution.
- Each reported control is one finite realization. Candidate/control ordering
  in a single extreme statistic is not by itself a calibrated significance
  test.
- The scan does not establish C1 PRF security, achieved security strength, or
  full-construction security.
- The scan does not cover `AuthContext`, M1 framing, long plaintext patterns,
  key-role relations, side channels, or faults; those remain separate roadmap
  work.

## Reproduction

```bash
CXX=g++ ./scripts/run_streamframe_domain_audit.sh build-streamframe-gcc
CXX=clang++ ./scripts/run_streamframe_domain_audit.sh build-streamframe-clang

# Exploratory replication reported above:
./build-streamframe-gcc/pvc-rotsymenc1-streamframe-domain-audit \
  --samples 4096 --walsh-variables 12 --walsh-trials 2 \
  --seed 0x53545245414D4632
```

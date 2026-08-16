# Attack Log

## 2026-08-16: Secret-key-dependent C1 timing

### Classification

Confirmed implementation-side timing leakage evidence on the tested x86-64
host. This is a side-channel observation, not a demonstrated key-recovery
attack, forgery, or break of the abstract full construction.

### Question

Does the current C1 implementation, and the M1/A1/RotSymEnc operations that use
it, show input-content-dependent execution time? In particular, does a signal
remain when the public StreamFrame is identical and only the secret key varies?

### Method and parameters

The official dudect header at commit `dc269651fb2567e46755cfb2a13d3875592968b5`
measured x86 TSC cycles on one pinned logical CPU. Each target used one discarded
12,000-measurement warm-up batch and three 12,000-measurement statistic batches,
balanced classes, 32-byte AD, 64-byte payloads, and 256-bit tags. GCC 14.2 and
Clang 19.1 Release builds were tested. Positive targets were repeated with a
second deterministic seed.

### Result

C1 crossed dudect's `|t| > 10` threshold under both seeds and compilers. In the
minimal key-only test, where the public StreamFrame was byte-identical, maximum
absolute t-statistics ranged from 102.54 to 154.16. The frame-only control was
also positive. The composite M1 tag generation, seal, failed open, and successful
open classes showed repeatable or dual-compiler timing separation. The isolated
M1 first-versus-last tag-mismatch position remained below threshold (`2.87` GCC,
`2.30` Clang).

### Interpretation and limitations

The key-only result is evidence that the current binary's execution time
depends on secret key content. Secret-derived C1 state selects coordinates,
axes, rotation amounts, branches, and memory locations, providing a structural
explanation. No practical key extraction, remote timing attack, or leakage-rate
estimate was attempted. Results remain CPU/compiler/OS dependent, and a
negative dudect result would not prove constant-time behavior. The composite
targets use C1, so their separation is consistent with propagation of the C1
behavior, but those classes do not establish that C1 is their only timing source.

### Reproduction

```bash
CXX=g++ ./scripts/run_timing_characterization.sh build-timing-gcc
CXX=clang++ ./scripts/run_timing_characterization.sh build-timing-clang
```

Full measurements and environment limitations are in
`TIMING_CHARACTERIZATION.md`.

## 2026-08-16: C1 on the Candidate A1 StreamFrame domain

### Classification

Bounded negative campaign. No attack or distinguisher was found at the tested
bounds. Untested keys, inputs, subspaces, and larger campaigns remain
inconclusive; the result does not establish that the hypotheses are globally
false.

### Question

Do valid structured `StreamFrame(N, i, t)` inputs expose full output merging,
related-input differential bias, output bias, or affine output components that
were hidden by C1's general-message campaigns?

### Method and parameters

The standalone audit used the canonical A1 frame writer and frozen C1 entry
point, seed `0x53545245414D4631`, 4,096 samples per stratum, all three tag
profiles, and two exact 12-variable Walsh trials in each of three domain
strata. GCC 14.2.0 and Clang 19.1.7 produced identical measurements. A second
seed, `0x53545245414D4632`, explored a same-direction primary Walsh extreme.

### Result

Both seeds produced zero defined alarms: no equal related outputs, census or
subspace collision, or affine output bit. The primary maximum candidate
absolute bit z-score was 3.4375. The initially same-direction global Walsh
maxima did not repeat under the second seed.

### Interpretation and limitations

The tested bounded hypotheses did not yield an attack. This is not a
full-construction attack, a proof of C1 pseudorandomness, or evidence for a
specific achieved security strength. The structured observations are not
independent Bernoulli samples, and the exact Walsh results cover only six
4,096-point subspaces.

### Reproduction

```bash
CXX=g++ ./scripts/run_streamframe_domain_audit.sh build-streamframe-gcc
CXX=clang++ ./scripts/run_streamframe_domain_audit.sh build-streamframe-clang
```

See `STREAMFRAME_DOMAIN_ANALYSIS.md` and the retained raw records for the full
measurement set.

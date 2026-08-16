# Attack Log

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

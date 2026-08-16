# Timing and Side-Channel Characterization

## Status

This document pre-registers an empirical timing-leakage campaign. It does not
change PVC-RotSymEnc-1, Candidate A1, M1, C1, or any canonical vector.

The complete primitive is not claimed to be constant-time. C1 is already known
from source inspection to use secret-dependent state coordinates, axes,
rotation amounts, and memory accesses. This campaign asks whether timing
differences are observable on the tested binary and host; it does not attempt
to prove constant-time behavior.

## Question

Can a two-class dudect campaign detect input-content-dependent timing in:

- direct C1 evaluation;
- M1 tag generation;
- the M1 supported-length comparison path;
- PVC-RotSymEnc-1 seal;
- failed open;
- successful open?

Two controls are included. An intentionally variable-time byte scan checks that
the environment can detect a large known leak. A valid-versus-invalid `open`
comparison characterizes the expected public control-flow difference caused by
verify-before-decrypt; it is not classified as a secret leak because acceptance
is already returned to the caller.

## Method

The harness uses the official dudect single-header implementation pinned at
commit `dc269651fb2567e46755cfb2a13d3875592968b5`. dudect records x86 TSC cycle
counts and applies first-order raw, cropped-percentile, and second-order Welch
t-tests. The runner pins the process to one allowed logical CPU.

All cryptographic classes have identical public lengths: 32-byte associated
data, 64-byte payload/ciphertext, and a 256-bit tag profile. Input preparation,
including generation of valid sealed messages, occurs outside the timed region.
Class order is exactly balanced and deterministically shuffled with SplitMix64.
SplitMix64 is experiment-only input generation and is not part of the candidate
construction.

| Target | Class 0 | Class 1 |
|---|---|---|
| positive control | first payload byte nonzero | last payload byte nonzero |
| C1 evaluate | fixed key and StreamFrame | random key and StreamFrame |
| C1 key localization | fixed key | random key, identical StreamFrame |
| C1 frame localization | fixed StreamFrame | random StreamFrame, identical key |
| M1 compute | fixed key/context/message | random key/context/message |
| M1 verify | first tag byte wrong | last tag byte wrong |
| seal | fixed tuple | random tuple |
| failed open | fixed invalid tuple | random invalid tuple |
| successful open | fixed valid tuple | random valid tuple |
| open validity control | invalid tag | valid tag |

The M1 verification classes share the same key, context, message, and expected
tag. Only the position of the one-byte mismatch changes, isolating the documented
content-independent comparison loop as far as the public API permits.

## Parameters

The primary campaign is fixed before result inspection:

```text
seed = 0x54494D494E473031
measurements per batch = 12000 (exactly balanced)
warm-up batches discarded = 1
statistics batches = 3
nominal retained measurements = about 36000 per target
dudect threshold = |t| > 10
build = GCC Release, followed by Clang Release comparison
host = x86-64 Intel Core i7-10710U, one pinned logical CPU
```

Every primary target with `|t| > 10` will be repeated with seed
`0x54494D494E473032`. The positive control must cross the threshold for the
host campaign to be considered sensitive to a large timing difference. A
repeated threshold crossing is evidence of timing leakage for that binary and
host, not evidence that a practical key-recovery attack exists.

If the combined C1 target crosses the threshold, two mandatory localization
targets use the same batch sizes before interpretation: key-only with an
identical public StreamFrame, and StreamFrame-only with an identical key. Both
are run under the primary and replication seeds and under GCC and Clang. This
separates evidence about secret-key-dependent execution from public-input cache
effects.

## Result

The primary and replication campaigns completed on Linux 6.12.95, an Intel
Core i7-10710U, and logical CPU 0. Each reported target retained approximately
36,000 measurements after the warm-up batch. The positive control crossed the
threshold in every compiler/seed campaign.

The principal maximum absolute t-statistics were:

| Target | GCC primary | GCC seed-2 | Clang primary | Classification |
|---|---:|---:|---:|---|
| positive control | 609.58 | 565.20 | 254.19 | expected positive |
| C1 combined key/frame | 111.48 | 117.66 | 144.18 | leakage evidence |
| M1 tag generation | 23.05 | 23.70 | 28.83 | leakage evidence |
| M1 mismatch position | 2.87 | not repeated | 2.30 | no evidence at bound |
| seal | 31.44 | 26.36 | 52.47 | leakage evidence |
| failed open | 48.58 | 68.80 | 25.09 | leakage evidence |
| successful open | 34.63 | 47.30 | 37.65 | leakage evidence |
| open valid/invalid control | 3447.81 | 1284.41 | 1661.70 | expected public difference |

Because the combined C1 classes changed both the key and frame, the mandatory
localization campaign separated them. Every localization run crossed the
threshold:

| Compiler | Seed | Key-only, identical frame | Frame-only, identical key |
|---|---|---:|---:|
| GCC 14.2 | primary | 124.40 | 101.93 |
| GCC 14.2 | seed-2 | 102.54 | 98.41 |
| Clang 19.1 | primary | 143.36 | 145.19 |
| Clang 19.1 | seed-2 | 154.16 | 135.30 |

The key-only classes kept the complete public StreamFrame byte string fixed.
Therefore the combined C1 signal cannot be explained only by public-input
cache reuse: the tested binaries exhibit repeatable secret-key-dependent timing
separation. Source inspection supplies a structural explanation: secret-derived
C1 state controls coordinates, axes, rotation amounts, conditional paths, and
cube memory locations.

The M1 mismatch-position result found no evidence of a first-byte early exit in
the documented comparison loop at this bound. That negative result does not
prove the loop or complete verification operation constant-time. The very large
valid-versus-invalid open difference is expected because valid open performs a
post-verification decrypt pass and invalid open returns after authentication.

Raw GCC primary, GCC seed-2, Clang primary, and C1 localization records are
retained under `results-0.1.0-draft/timing/`.

## Interpretation

This campaign falsifies a constant-time hypothesis for the current C1 binary on
the tested host and provides repeatable evidence that the timing depends on the
secret key. M1 tag generation and the complete seal/open operations use C1, and
their composite classes also showed timing separation. This is consistent with
propagation of the C1 behavior, but those classes vary multiple inputs and do
not establish C1 as their only timing source. Constant-time behavior was already
outside the project's stated claims, but C1 key dependence is now an observed
implementation weakness rather than only a source-level warning.

The result does not show how many observations an attacker would need, which
key information is recoverable, whether the signal survives a network, or
whether a practical attack exists. It is not a confidentiality or forgery
break of the abstract construction.

## Limitations

- dudect leakage detection is not a timing attack and does not quantify key
  recovery or remote exploitability.
- Failure to cross the threshold does not prove constant-time execution.
- Results depend on CPU, cache hierarchy, microcode, compiler, flags, kernel,
  power management, background load, and sample design.
- CPU affinity does not disable interrupts, SMT sibling activity, turbo boost,
  or frequency scaling on the test host.
- Fixed-versus-random classes can amplify cache reuse and branch-prediction
  effects. This is useful for falsification but is not a remote threat model.
- The x86 RDTSC backend does not cover ARM, Windows, macOS, power, EM, or other
  physical leakage channels.
- The public valid-versus-invalid open timing difference is expected from
  verify-before-decrypt and is not by itself an authentication bypass.

## Reproduction

```bash
CXX=g++ ./scripts/run_timing_characterization.sh build-timing-gcc
CXX=clang++ ./scripts/run_timing_characterization.sh build-timing-clang

# Second-seed replication of a single positive target:
taskset -c 0 ./build-timing-gcc/pvc-rotsymenc1-timing-characterization \
  --target c1-evaluate --measurements 12000 --batches 3 \
  --seed 0x54494D494E473032
```

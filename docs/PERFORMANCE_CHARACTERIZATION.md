# Performance Characterization

## Status

This document pre-registers the primary local campaign before its full run.
The exploratory 1 MiB smoke used only to size the campaign is not a retained
performance result. The candidate construction and canonical vectors are
unchanged.

## Question

What latency, payload throughput, invariant-TSC cost, and isolated-process
resident-memory footprint does the canonical PVC-RotSymEnc-1 wrapper exhibit
for the RoadMap message sizes and tag profiles on the primary local host?

## Method

`pvc-rotsymenc1-performance-benchmark` measures the public `seal` API and a
successful public `open` API call. The build is `Release`/`NDEBUG` with warnings
as errors. API-owned output allocation and destruction are inside the timed
region. Deterministic input preparation and the valid ciphertext/tag creation
needed by `open` are outside it.

Every measured call checks its length contract; successful `open` also checks
the complete returned plaintext against the prepared plaintext. A sink derived
from the outputs prevents dead-result elimination. The fixed benchmark tuple is
generated with SplitMix64 seed `0x50455246424D4B31`; no randomness is sampled
during measurement. Reusing the fixed nonce is confined to discarded benchmark
outputs and is not a model for permitted encryption use.

Each configuration runs in a fresh process pinned to the first CPU in the
caller's allowed affinity. A discarded calibration phase selects the smallest
batch expected to last at least 100 ms, subject to a 1,048,576-iteration cap.
The retained statistic is the median of five samples below 64 KiB and three
samples at or above 64 KiB. Cases run in size, tag-profile, then operation order.

The primary campaigns use the same Intel Core i7-10710U Linux x86-64 host as
the timing characterization, once with GCC 14.2 and once with Clang 19.1. The
runner records the exact compiler, kernel, CPU affinity, frequency driver,
governor, observed start/end frequency, Git commit, and benchmark binary hash.

## Parameters

```text
message bytes = 0, 16, 64, 256, 1024, 4096, 65536, 1048576
associated data bytes = 32
tag bits = 128, 192, 256
operations = seal, successful open
samples = 5 below 65536 bytes; 3 at or above 65536 bytes
target batch duration = 100 ms
maximum iterations per sample = 1048576
seed = 0x50455246424D4B31
```

This produces 48 isolated configurations per compiler.

## Metrics

- Median latency is wall-clock nanoseconds per API call.
- MiB/s uses plaintext/ciphertext payload bytes only. It is undefined for the
  zero-byte cases.
- x86 `RDTSCP` with load fences records invariant-TSC ticks per call and per
  payload byte. These are reference-clock ticks, not dynamic core-cycle
  performance-counter measurements, so the report does not label them as
  literal CPU cycles.
- `getrusage(RUSAGE_SELF).ru_maxrss` records peak resident KiB before and after
  the measurement in each isolated process. It is a coarse process-level
  footprint affected by the loader, runtime, allocator, prepared inputs, and
  retained high-water behavior; it is not a precise heap-allocation profile.
- API-visible input and output buffer byte counts are retained separately from
  resident memory.

No pass/fail performance threshold is defined. Compiler-to-compiler or
tag-profile differences will be reported as observations, not security
properties. Standard algorithms may be measured later only as explicitly
separate external controls; none is linked into this benchmark or candidate.

## Acceptance Criteria

- both warnings-as-errors Release builds complete;
- all 48 configurations complete for both compilers;
- every successful `open` returns the exact prepared plaintext;
- latency is positive and nonzero-payload throughput is positive;
- raw samples and full environment metadata are retained;
- construction sources and canonical vectors remain unchanged.

## Result

Pending the pre-registered primary campaigns.

## Interpretation

Pending measurement.

## Limitations

- The primary campaign covers one x86-64 laptop-class CPU and two compilers.
- CPU pinning does not disable interrupts, SMT interference, frequency scaling,
  turbo behavior, thermal effects, or other operating-system noise.
- Median values from three or five samples provide characterization, not a
  stable service-level guarantee or a cross-machine performance claim.
- Inputs are hot and deterministic; cold-cache, multi-threaded, streaming,
  concurrent, and adversarial scheduling behavior is not measured.
- Allocation cost is part of the current public API result and cannot be
  separated without measuring a different interface.
- Performance says nothing about cryptographic security.

## Reproduction

After the benchmark-definition commit, run from a clean tracked worktree:

```bash
CXX=g++ ./scripts/run_performance_benchmark.sh \
  build-performance-gcc results-0.1.0-draft/performance/GCC14_PRIMARY.json \
  --require-tsc
CXX=clang++ ./scripts/run_performance_benchmark.sh \
  build-performance-clang results-0.1.0-draft/performance/CLANG19_PRIMARY.json \
  --require-tsc
python3 scripts/summarize_performance_benchmark.py --verify-only \
  results-0.1.0-draft/performance/GCC14_PRIMARY.json \
  results-0.1.0-draft/performance/CLANG19_PRIMARY.json
```

# Performance Characterization

## Status

This document pre-registers the primary local campaign. Attempt 1 exposed an
invalid resident-memory metric and is retained separately; the amended metric
below was fixed before the replacement primary run. The latency, TSC, corpus,
sample-count, and ordering definitions were not changed. The exploratory 1 MiB
smoke used only to size the campaign is not a retained performance result. The
candidate construction and canonical vectors are unchanged.

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
- On Linux, `/proc/self/statm` records current resident KiB before and after the
  measurement and immediately after each timed batch while its final API output
  remains live. The maximum retained-output sample is the reported footprint.
  It is a coarse process-level value affected by the loader, runtime, allocator,
  prepared inputs, and page residency; it is not a precise heap-allocation
  profile or an all-instruction peak.
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

Attempt 1 completed 48 cases with each compiler, but its `ru_maxrss` fields are
invalid. Linux preserves the launcher's pre-`exec` high-water value: an
otherwise identical zero-byte benchmark reported approximately 11 MiB when
launched by the Python runner and 16 MiB when launched directly by the shell.
The latency and TSC measurements did not depend on that field, but the complete
attempt is classified as superseded rather than selectively accepted.

The raw attempt is retained as:

```text
results-0.1.0-draft/performance/GCC14_ATTEMPT1_INVALID_RSS.json
results-0.1.0-draft/performance/CLANG19_ATTEMPT1_INVALID_RSS.json
```

The replacement benchmark/runner version 2 campaigns completed 48/48 cases
with each compiler. Every successful `open` returned the exact prepared
plaintext. The primary summaries are:

| Compiler | 0 B latency | 4 KiB | 64 KiB | 1 MiB | 1 MiB TSC ticks/byte |
|---|---:|---:|---:|---:|---:|
| GCC 14.2 | 0.569-0.576 ms | 0.0656-0.0662 MiB/s | 0.0662-0.0665 MiB/s | 0.0661-0.0664 MiB/s | 23093-23186 |
| Clang 19.1 | 0.443-0.450 ms | 0.0842-0.0866 MiB/s | 0.0887-0.0890 MiB/s | 0.0777-0.0889 MiB/s | 17253-19733 |

The low endpoint and high TSC endpoint in the Clang 1 MiB range are the same
128-bit successful-open row. It was stable within that three-sample process but
was not reproduced: a targeted 128/192-bit replication measured 0.088548 and
0.088624 MiB/s respectively, a difference of about 0.09%. Attempt 1 had also
measured that 128-bit case near the other profiles. The primary observation is
retained, but it is not evidence of a stable 128-bit tag cost.

Excluding that non-reproduced row, Clang was 1.275-1.342 times faster than GCC
for matched cases including zero-byte calls, with a median ratio of 1.297.
Tag-profile latency spread at a
fixed compiler/operation/size was at most 1.1% for GCC and 3.2% for Clang after
the same exclusion. GCC successful-open/seal ratios stayed within 0.990-1.009;
Clang's median ratio was 1.002, with wider individual noise. Retained-sample
range divided by median was at most 2.68% for GCC and 4.78% for Clang overall;
for 1 MiB it was at most 0.59% and 1.75% respectively.

At 1 MiB, current RSS with the final output retained was 7,580-7,588 KiB for
GCC seal and 6,564-6,572 KiB for GCC open. Clang reported 7,508-7,568 KiB for
seal and 6,488-6,552 KiB for open. Zero-byte cases were approximately
3,440-3,540 KiB. These are process-level resident values under the stated
limitations, not allocation counts.

As a separate external control, OpenSSL 3.5.6 `speed -aead` on the same pinned
CPU reported 4,150.667/4,178.333 MiB/s for AES-256-GCM encrypt/decrypt and
2,202.667/2,191.667 MiB/s for ChaCha20-Poly1305 encrypt/decrypt at 1 MiB.
Those values are about 24,600-63,200 times the recorded candidate throughput.
This is not an API-equivalent comparison: OpenSSL is an optimized system
library with hardware acceleration, different allocation behavior, and a
TLS-like benchmark path. It is retained only as an external scale control.

## Interpretation

On this host, fixed-call overhead dominates tiny messages and throughput levels
off by 4-64 KiB. The plateau is consistent with the current reference path's
one C1 evaluation per 32-byte stream block; the campaign does not isolate every
source of cost. The measured implementation is extremely slow relative to the
separate system-library controls. This is an implementation/performance result,
not evidence for or against cryptographic security.

No stable tag-profile performance ordering was found. The non-reproduced Clang
row demonstrates why individual long-running rows must not be converted into a
structural claim without replication.

## Limitations

- The primary campaign covers one x86-64 laptop-class CPU and two compilers.
- CPU pinning does not disable interrupts, SMT interference, frequency scaling,
  turbo behavior, thermal effects, or other operating-system noise.
- Median values from three or five samples provide characterization, not a
  stable service-level guarantee or a cross-machine performance claim.
- Inputs are hot and deterministic; cold-cache, multi-threaded, streaming,
  concurrent, and adversarial scheduling behavior is not measured.
- Allocation cost is part of the current public API result and cannot be
  separated without measuring a different interface. The retained-output RSS
  metric does not capture a transient peak that occurs earlier in a call.
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

The targeted replication is reproduced with:

```bash
python3 scripts/run_performance_benchmark.py \
  --benchmark build-performance-clang/pvc-rotsymenc1-performance-benchmark \
  --output results-0.1.0-draft/performance/CLANG19_1M_OPEN_REPLICATION.json \
  --sizes 1048576 --tags 128,192 --operations open-success \
  --samples 3 --large-samples 3 --target-ms 100 \
  --require-clean --require-tsc
```

The external controls use the system OpenSSL build and are reproduced one case
at a time, adding `-decrypt` for the decrypt rows:

```bash
taskset -c 0 openssl speed -elapsed -seconds 3 -bytes 1048576 \
  -aead -evp aes-256-gcm
taskset -c 0 openssl speed -elapsed -seconds 3 -bytes 1048576 \
  -aead -evp chacha20-poly1305
```

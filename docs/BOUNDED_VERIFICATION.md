# CBMC Bounded Implementation Verification

## Question

Can bounded model checking reject implementation defects in Candidate A1's
frame writing, tag-length gate, verify-before-decrypt ordering, payload-length
preservation, block count, and 64-bit counter arithmetic without changing the
cryptographic construction?

## Method

CBMC 6.10.0 analyzes a verification translation of the pinned
`external/pvc_aead0_a1/src/aead.cpp` source. The runner first requires the exact
source SHA-256
`92ddd474cae8c173bd16df5aca3b88c34c8af431cecf7727a90fb6298a71160d`.
It then applies the documented parse-only adapter in
`verification/cbmc/prepare_aead.sed` because CBMC's C++ frontend does not parse
the project's C++20 STL or anonymous namespace directly.

The translation retains the A1 function bodies and uses bounded models for the
small subset of `array`, `vector`, `span`, and `optional` that those bodies use.
The model requires every frame write to remain inside the size passed to
`reserve`. Candidate C1 output and Candidate M1 verification are external
stubs: stream bytes are arbitrary, and verification may return either result.
The PRF stub asserts that an `open` call cannot reach it before a successful M1
verification.

The counter harness separately evaluates the exact block-count expression over
the complete unsigned 64-bit payload-length domain and enables CBMC's unsigned
overflow checks.

## Parameters

- CBMC: `6.10.0 (cbmc-6.10.0)`, x86-64 Linux model
- C++ unwind bound: 82, with unwinding assertions enabled
- modeled vector capacity: 80 bytes
- frame harness: arbitrary 192-bit nonce, arbitrary 64-bit counter, all three
  tag profiles, associated-data lengths 0 through 16
- `seal` harness: arbitrary bytes, plaintext lengths 0 through 33,
  associated-data lengths 0 through 8, all three tag profiles
- `open` harness: arbitrary bytes, ciphertext lengths 0 through 33,
  associated-data lengths 0 through 8, every 64-bit `size_t` tag length, and
  both M1 verification outcomes
- counter harness: every value in the unsigned 64-bit payload-length domain
- pointer object bits: 12

The payload bound crosses the 32-byte stream-block boundary, so zero-, one-,
and two-block executions are reachable.

## Result

The local campaign on 2026-08-16 completed with no failed selected property or
unwinding assertion:

| Harness | Observed result |
|---|---|
| `verify_frames` | 278/278 reachable target, automatic safety, and unwinding properties passed |
| `verify_seal_lengths` | 8/8 selected target and reachable unwinding properties passed |
| `verify_open_control_flow` | 19/19 selected target and reachable unwinding properties passed |
| `counter_harness.c` | 9/9 assertions and overflow properties passed |

The checked control-flow properties include:

- only tag lengths 16, 24, and 32 reach M1 verification;
- invalid tag lengths do not reach the decrypt/PRF path;
- failed verification does not reach the decrypt/PRF path or return plaintext;
- every reached decrypt block follows a successful verification;
- `seal` ciphertext length equals plaintext length within the stated bound;
- successful `open` plaintext length equals ciphertext length within the stated
  bound;
- the exact frame reservations contain all frame writes within the stated
  bound;
- every admissible 64-bit payload length uses at most `2^59` stream blocks, so
  the counter and final block offset do not wrap.

## Interpretation

This campaign provides bounded evidence against the listed implementation
failure modes. The verification outcome is sensitive to the pinned source,
models, bounds, selected assertions, and CBMC version. It is not a proof of C1
PRF security, M1 unforgeability, A1 AEAD security, or production suitability.

## Limitations

- The C++ checks use verification container models, not the libstdc++ allocator
  and container implementation. ASan, UBSan, MSan, fuzzing, and native tests
  cover that separate runtime surface.
- C1 internals and M1 internals are stubbed. The arbitrary verification result
  is deliberate and checks composition ordering, not tag correctness.
- `seal` and `open` payload/AD properties are bounded as stated. Larger native
  executions are not established by these harnesses.
- The full-domain tag-length check overapproximates the span's backing storage.
  Invalid-length paths inspect only the size and return before reading tag
  bytes.
- The full-domain counter result is an arithmetic proof harness corresponding
  to A1's block-count expression; it does not unroll `2^59` loop iterations.
- Parse adaptations replace unsupported C++ syntax with equivalent C++11 model
  syntax. The source hash guard prevents silently applying this evidence to a
  changed A1 implementation.
- No timing, cache, power, fault, concurrency, or side-channel property is
  modeled.

## Reproduction

Use the pinned official CBMC 6.10.0 executable and run:

```bash
CBMC=/path/to/cbmc ./scripts/run_cbmc.sh
```

Detailed logs and the generated verification translation are written under
`build-cbmc/`, which is ignored by Git.

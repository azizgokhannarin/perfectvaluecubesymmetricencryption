# Software Fault-Injection Campaign

## Status

This document pre-registers campaign version 1. Results are pending. The
candidate construction, public `seal`/`open` API, vendored C1/M1/A1 sources,
and canonical vectors are unchanged. All fault mechanisms are confined to a
standalone analysis executable.

## Question

Under explicit single-software-fault models, which data faults are rejected by
the canonical wrapper, which modeled control-flow faults bypass the single
authentication gate, and how do finalization-adjacent C1 state faults propagate
into stream or MAC outputs?

## Method

The campaign separates three evidence classes:

1. Canonical-wrapper experiments alter actual nonce, ciphertext, tag, AD, or
   tag length and call the unmodified public `open` implementation.
2. Post-authentication data-fault models first establish a successful canonical
   verification, then use the frozen public framing/C1 functions to alter the
   stream counter or nonce used during modeled decryption.
3. Explicit control-flow models omit one tag-comparison byte, corrupt the loop
   length after profile validation, or skip the failed-authentication return.
   These are models of removed operations, not claims that the compiled binary
   has been physically faulted.

C1 state injection uses the frozen research APIs. A canonical keyed
forward/return state is computed, one of its 4,224 modeled bits is flipped, and
the unmodified controller-bound finalizer is invoked. The injection point is
after transcript return and immediately before finalization. The modeled state
contains 4,096 cube-cell bits and 128 controller bits.

## Parameters

```text
campaign version = 1
construction version = 0.1.0-draft
deterministic seed = 0x4641554C54494E4A
tag profiles = 128, 192, 256 bits
AD bytes per profile = 33
plaintext bytes per profile = 96
canonical tag-bit faults = 576
MAC-result bit faults = 576
skipped comparison-byte faults = 72
pre-validation tag-length faults = 18
post-validation tag-length model faults = 3
authentication-branch skip variants = 12
post-authentication counter faults = 192
post-authentication nonce faults = 192
C1 stream-state faults = 4,224
C1 MAC-state faults = 4,224 per tag profile
compilers = GCC 14.2 and Clang 19.1 on GNU/Linux
sanitizers = Clang AddressSanitizer and UndefinedBehaviorSanitizer
```

## Pre-Registered Expectations

- Canonical `open` rejects every one-bit supplied-tag mutation, actual resized
  tag, and altered nonce/AD/ciphertext/tag control tuple.
- Flipping one recomputed MAC-result bit makes the correct supplied tag fail;
  this is an availability fault, not an authentication bypass.
- If the only mismatching tag byte is also the comparison iteration removed by
  the explicit model, all 72 modeled comparisons accept.
- A post-validation length fault that reduces the modeled comparison to zero or
  omits the only mismatching suffix accepts in all three registered cases.
- Skipping the failed-authentication return releases modeled decryption output
  for all 12 altered tuples. Some releases retain the original plaintext while
  losing AD/tag binding; ciphertext/nonce mutations should corrupt plaintext.
- Counter and nonce faults after successful authentication may corrupt released
  plaintext because Encrypt-then-MAC authenticates inputs, not the correctness
  of later computation. Silent cases, if any, will be retained rather than
  converted into test failures.
- No direction is assumed for C1 state-fault distances. Unchanged tag prefixes,
  unchanged stream outputs, or one-bit tag-prefix distances are findings to be
  reported, not automatically discarded as harness failures.

Any canonical acceptance of an altered tuple, baseline mismatch, sanitizer
finding, compiler disagreement, or result outside the explicitly modeled
control-flow bypasses is an alarm.

## Result

Pending the first campaign run after this definition is committed.

## Interpretation

Pending measurement. Modeled comparison or branch removal demonstrates the
logical consequence of the removed operation. It does not establish voltage,
clock, laser, electromagnetic, Rowhammer, or remote fault feasibility.

## Limitations

- The campaign is software-level and deterministic; it does not characterize a
  physical injection apparatus, timing window, success probability, or attacker
  control precision.
- The C1 fault point is one boundary near finalization. Earlier key-schedule,
  forward-pass, return-pass, and squeeze-round injection timings are excluded.
- One-bit state faults cover cube cells and controller words, not cursor,
  previous-axis, symbol-index, code, pointers, allocator metadata, registers,
  caches, or instruction bytes.
- The comparison and branch-skip models deliberately remove operations in an
  analysis helper. They do not mutate the production binary or prove that one
  physical fault can realize the modeled effect.
- Fault combinations, persistent faults, instruction replacement, key
  extraction, differential fault analysis, and practical forgery workflows are
  excluded.
- A bounded negative result is not evidence of fault resistance or general
  cryptographic security.

## Reproduction

```bash
CXX=g++ ./scripts/run_fault_injection_campaign.sh build-fault-gcc
CXX=clang++ ./scripts/run_fault_injection_campaign.sh build-fault-clang
BUILD_TYPE=RelWithDebInfo SANITIZER=address CXX=clang++ \
  ./scripts/run_fault_injection_campaign.sh build-fault-asan
BUILD_TYPE=RelWithDebInfo SANITIZER=undefined CXX=clang++ \
  ./scripts/run_fault_injection_campaign.sh build-fault-ubsan
```

# Nonce Management And Misuse Campaign

## Status

Campaign version 1 completed on 2026-08-16. Its definition was committed as
`5a674eb` before the first measurement. The candidate construction, public
`seal`/`open` API, and canonical vectors are unchanged. All management code is
an analysis-only research prototype.

## Question

Which nonce-reuse consequences and state-management failure modes can be
reproduced around PVC-RotSymEnc-1 without changing Candidate A1, and which are
prevented by an in-memory reuse detector or a locked persistent 192-bit counter?

## Method

The campaign uses the canonical public wrapper to reproduce same-key/same-nonce
keystream reuse. Separate analysis-only prototypes provide:

- an exact in-memory set keyed by the complete `K_enc` and 192-bit nonce;
- a deterministic collision simulator, clearly separate from the construction;
- a file-backed 192-bit big-endian counter serialized by a separate lock file;
- write-to-temporary, file `fsync`, atomic replacement, and directory `fsync`
  before an allocated nonce returns;
- an explicit non-secret 128-bit scope identifier supplied per encryption key.

The persistent prototype stores neither encryption keys nor key-derived values.
It rejects a state file opened with a different scope. Its state record contains
complement redundancy for accidental corruption detection; this is not a MAC
and the storage directory is assumed non-adversarial.

## Parameters

```text
campaign version = 1
construction version = 0.1.0-draft
deterministic simulator seed = 0x4E4F4E43454D4754
full-width simulation = 65,536 nonces at 192 bits
reduced collision control = 256 trials x 4,096 samples at 24 bits
normal restart allocations = 257
injected process-crash points = 4
multi-process workers = 8
allocations per worker = 128
snapshot rollback branch = 8 allocations
compilers = GCC 14.2 and Clang 19.1 on GNU/Linux
sanitizers = Clang AddressSanitizer and UndefinedBehaviorSanitizer
```

The four injected process-crash points are after acquiring the lock, after
synchronizing the temporary state, after replacing the active state, and after
synchronizing the containing directory. A child terminates immediately at the
selected point. This models process termination and restart, not sudden power
loss or dishonest storage.

## Pre-Registered Expectations

- Same `K_enc`, nonce, and tag profile reproduce the ciphertext/plaintext XOR
  relation over every overlapping byte; valid tags do not repair disclosure.
- The reuse detector rejects a second observation under the same `K_enc`, even
  if an application intended to change tag profile, and allows the same nonce
  under a different `K_enc`.
- The fixed 192-bit sample has no collision. The reduced 24-bit control has at
  least one collision. Neither is a statistical security proof.
- Repeated normal reopening produces a contiguous unique sequence and a scope
  mismatch is rejected without consuming a nonce.
- A process crash before active-state replacement preserves the old next value;
  a crash after replacement preserves the advanced value. Because no injected
  call returns, the subsequent caller receives no previously returned nonce.
- All 1,024 concurrent allocations are unique and gap-free.
- Restoring an earlier state snapshot repeats the post-snapshot nonce sequence.
  An in-memory detector that was not also rolled back observes those repeats.

The XOR disclosure and snapshot rollback repeat are expected known misuse
findings, not unexpected campaign failures. Any detector miss, returned-nonce
reuse in the process-crash model, counter collision/gap, invalid scope
acceptance, sanitizer finding, or compiler disagreement is an alarm.

## Result

GCC 14.2 and Clang 19.1 Release runs produced byte-identical records. Clang
AddressSanitizer and UndefinedBehaviorSanitizer runs produced the same record
and reported no candidate-path finding. LeakSanitizer could not run locally
because the managed environment is `ptrace`-restricted, so the retained local
ASan run used `detect_leaks=0`; CI keeps leak detection enabled.
GitHub Actions run `31971780631` passed all 23 jobs, including all four nonce
campaign profiles on hosted GNU/Linux runners.

- The exact detector observed same-key reuse and did not classify the same
  nonce under a different key as reuse.
- Reusing a key and nonce reproduced the ciphertext/plaintext XOR relation for
  all 96 tested bytes. Both messages still authenticated successfully.
- The 65,536-sample 192-bit simulation had zero collisions, with birthday
  expectation `3.421087e-49`. The 24-bit control observed 129 collisions versus
  expectation `1.279688e+02`.
- All 257 restart allocations were unique and contiguous. A different scope
  was rejected without changing the state.
- Across four process-crash points, two resumes used the preserved old state
  and two used the persisted advanced state. No nonce previously returned to a
  caller was returned again.
- Eight processes made 1,024 unique, gap-free allocations.
- Restoring a saved state file repeated all eight post-snapshot nonces. The
  independent in-memory detector, which was not rolled back, caught all eight.

The pre-registered unexpected-failure count was zero. The XOR disclosure and
snapshot rollback repeat were the two expected known misuse findings.

## Interpretation

Within the tested process-crash and local-filesystem model, write-ahead state
persistence and inter-process locking prevented reuse of a nonce that had
already been returned. This does not make the construction nonce-misuse
resistant. Snapshot restoration defeats the counter unless an external
non-rollbackable authority or durable reuse history is present.

The 192-bit collision simulation is consistent with its negligible birthday
expectation at this sample count, while the reduced-width control shows that
the campaign can observe collisions. It does not validate a random-number
generator or prove collision freedom.

## Limitations

- The persistent allocator is a research prototype, not a supported public API.
- Linux `flock`, `rename`, and `fsync` behavior is tested on local and hosted
  filesystems; network filesystems and other operating systems are excluded.
- Process termination does not reproduce power loss, storage-controller lies,
  filesystem bugs, disk corruption, VM snapshot rollback, or cloned state.
- The caller must provision and preserve a unique scope/path per `K_enc`.
- The reuse detector is in-memory and itself loses history on restart or state
  rollback unless an independent durable service preserves it.
- The deterministic simulator is not a cryptographic random nonce generator.
- No result is evidence for C1 PRF security, M1 unforgeability, or full AEAD
  security.

## Reproduction

```bash
CXX=g++ ./scripts/run_nonce_misuse_campaign.sh build-nonce-misuse-gcc
CXX=clang++ ./scripts/run_nonce_misuse_campaign.sh build-nonce-misuse-clang
BUILD_TYPE=RelWithDebInfo SANITIZER=address CXX=clang++ \
  ./scripts/run_nonce_misuse_campaign.sh build-nonce-misuse-asan
BUILD_TYPE=RelWithDebInfo SANITIZER=undefined CXX=clang++ \
  ./scripts/run_nonce_misuse_campaign.sh build-nonce-misuse-ubsan
```

Retained raw records and environment details are under
`results-0.1.0-draft/nonce-misuse/`.

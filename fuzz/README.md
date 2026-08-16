# Differential Fuzzing

## Question

Do the public PVC-RotSymEnc-1 wrapper and the independent Candidate A1
implementation disagree for any generated `seal` or `open` input?

## Method

Two Clang libFuzzer targets exercise separate behavior:

- `pvc-rotsymenc1-fuzz-seal-equivalence` maps every fuzzer input to a valid
  key pair, nonce, tag profile, associated-data string and plaintext, then
  requires byte-identical ciphertext and tag output.
- `pvc-rotsymenc1-fuzz-open-equivalence` compares acceptance, rejection and
  returned plaintext for arbitrary ciphertext/tag tuples. A second input mode
  uses the independent implementation to synthesize valid tuples so the
  authenticated decryption branch remains reachable during mutation.

The fuzz build instruments the wrapper and the complete vendored C1/M1/A1
call tree with SanitizerCoverage, AddressSanitizer and UndefinedBehaviorSanitizer.
The fuzzer harnesses use only the public APIs and do not modify the construction.

## Input Encoding

Fixed-width fields missing from a short input are zero-filled.

The `seal` target consumes:

```text
byte 0       tag-profile selector modulo 3
bytes 1..2   big-endian AD/plaintext split hint
bytes 3..34  encryption key
bytes 35..66 authentication key
bytes 67..90 nonce
remaining    AD || plaintext
```

The `open` target consumes:

```text
byte 0       mode: even = raw tuple, odd = generated valid tuple
byte 1       tag-size/profile selector
bytes 2..3   big-endian payload split hint
bytes 4..35  encryption key
bytes 36..67 authentication key
bytes 68..91 nonce
remaining    mode-specific payload
```

In raw mode, selectors `a`, `b` and `c` request 16-, 24- and 32-byte tags;
other selector values request their literal byte value, including unsupported
lengths. Tag material comes from the payload suffix and is zero-filled when
short. The preceding body is split into AD and ciphertext.

In generated-valid mode, the selector chooses one of the three supported tag
profiles and the payload is split into AD and plaintext. Independent A1 seals
that tuple; both open implementations must accept it and recover the input
plaintext.

## Build

```bash
CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DPVCROTSYMENC1_BUILD_FUZZERS=ON \
  -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
cmake --build build-fuzz \
  --target pvc-rotsymenc1-fuzz-seal-equivalence \
           pvc-rotsymenc1-fuzz-open-equivalence --parallel
```

## Deterministic Smoke Campaign

CTest uses seed `1`, 256 runs per target and a maximum input length of 4,096
bytes. Newly retained corpus entries are written under the build tree, never
into the checked-in seed corpus.

```bash
ctest --test-dir build-fuzz -L fuzz --output-on-failure
```

LeakSanitizer cannot initialize under some `ptrace`-restricted sandboxes. Only
for that documented runner limitation, the smoke campaign can be repeated as:

```bash
ASAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir build-fuzz -L fuzz --output-on-failure
```

This leaves AddressSanitizer and UndefinedBehaviorSanitizer instrumentation
active but disables leak detection. It must not be used to dismiss an actual
leak report, and CI retains the default leak check.

## Longer Campaign

```bash
mkdir -p build-fuzz/corpus/seal build-fuzz/corpus/open \
         build-fuzz/artifacts/seal build-fuzz/artifacts/open

./build-fuzz/pvc-rotsymenc1-fuzz-seal-equivalence \
  -max_len=4096 -max_total_time=3600 -print_final_stats=1 \
  -artifact_prefix=build-fuzz/artifacts/seal/ \
  build-fuzz/corpus/seal fuzz/corpus/seal-equivalence

./build-fuzz/pvc-rotsymenc1-fuzz-open-equivalence \
  -max_len=4096 -max_total_time=3600 -print_final_stats=1 \
  -artifact_prefix=build-fuzz/artifacts/open/ \
  build-fuzz/corpus/open fuzz/corpus/open-equivalence
```

Record the libFuzzer seed, run count or time budget, maximum input length,
compiler version and sanitizer configuration with every retained result.

## Result Interpretation

A crash indicates an implementation mismatch, sanitizer finding or violated
harness property and must be minimized and investigated. A completed campaign
means only that no discrepancy was found within that compiler, corpus and
budget. It does not establish PRF, MAC or AEAD security.

Both A1 implementations share the frozen C1 implementation. These targets can
detect wrapper, framing, composition and API-behavior differences, but they are
not independent evidence for the security or correctness of the C1 core.

The first fixed-seed campaign is retained in
`fuzz/results/INITIAL_2026-08-16.md`.

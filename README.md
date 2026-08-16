# Perfect Value Cube Symmetric Encryption

`PVC-RotSymEnc-1` is the public symmetric-encryption profile of the frozen Perfect Value Cube keyed construction line.

It does **not** introduce a new cryptographic primitive or modify the frozen construction. Version `0.1.0-draft` is defined to be byte-exactly equivalent to:

- `PVC-PRF-1` Candidate C1 / v0.9.0;
- `PVC-MAC-0` Candidate M1 / v0.2.0;
- `PVC-AEAD-0` Candidate A1 / v0.2.0.

The public algorithm path is:

```text
K_enc, K_mac, nonce, AD, plaintext
        |
        v
PVC-AEAD-0 Candidate A1
  - C1 nonce+counter keystream
  - M1 encrypt-then-MAC authentication
        |
        v
ciphertext, tag
```

> Research software only. Do not use PVC-RotSymEnc-1 to protect production data, credentials, firmware, financial transactions, safety-critical systems, or other real secrets.

## Current status

| Item | Status |
|---|---|
| Public algorithm | PVC-RotSymEnc-1 |
| Repository draft | 0.1.0-draft |
| Cryptographic construction | byte-exact Candidate A1 / v0.2.0 |
| Encryption key | independent 256-bit `K_enc` |
| Authentication key | independent 256-bit `K_mac` |
| Nonce | 192-bit, unique under each `K_enc` |
| Tag profiles | 128 / 192 / 256 bits |
| New cryptographic mixing in this repo | none |
| Production-ready | no |
| Proven bit security | no |
| Quantified post-quantum security | no |
| Nonce-misuse resistant | no |

## Public-review entry points

- `SPECIFICATION.md` — normative PVC-RotSymEnc-1 profile.
- `CRYPTANALYSIS_CHALLENGE.md` — review and falsification targets.
- `docs/SECURITY_TARGET.md` — targets and explicit non-claims.
- `docs/ARCHITECTURE.md` — C1 → M1 → A1 → RotSymEnc layering.
- `docs/COMPONENT_PROVENANCE.md` — exact frozen dependencies and upstream repositories.
- `docs/SPEC_FREEZE.md` — draft/freeze policy.
- `docs/INDEPENDENT_REVIEW.md` — reviewer workflow.
- `docs/TRUST_PATH_ROADMAP.md` — path from draft wrapper to public release candidate.
- `test-vectors/` — retained Candidate A1 KAT and differential corpora.

## Design boundary

PVC-RotSymEnc-1 embeds no AES, ChaCha, SHA, Keccak, BLAKE, imported S-box, standard KDF, external MAC, or external pseudorandom generator.

This repository also adds **no new Perfect Value Cube mixing step**. Its cryptographic definition is the already frozen Candidate A1 construction. Any change to C1, M1, A1, their frames, counter layout, tag computation, nonce profile, key roles, or encrypt-then-MAC ordering requires a new cryptographic candidate identifier.

## Normative construction

For tag profile `t ∈ {128,192,256}`:

```text
Z_i = C1_Kenc(StreamFrame(N, i, t))
C   = P XOR Z
A   = AuthContext(N, AD, t)
T   = M1_Kmac(A, C, t)
```

`open` authenticates `N`, `AD`, `C`, and the tag profile before deriving or returning plaintext.

Two independent 256-bit role keys are required. This repository deliberately defines no master-key KDF.

Nonce reuse under the same `K_enc` is forbidden. Reusing a nonce repeats the keystream and reveals the XOR of equal-length plaintext prefixes.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For a broader wrapper-to-A1 equivalence campaign:

```bash
./build/pvc-rotsymenc1-equivalence --count 4096
```

## Sanitizer and optimization matrix

`PVCROTSYMENC1_SANITIZER` selects an opt-in whole-tree test profile: `address`,
`undefined`, or `memory`. The default is `none`. MemorySanitizer requires
upstream Clang on Linux, FreeBSD, or NetBSD; it enables origin tracking level 2.
Sanitizer profiles and libFuzzer profiles are intentionally separate.

```bash
CC=clang CXX=clang++ cmake -S . -B build-msan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DPVCROTSYMENC1_SANITIZER=memory
cmake --build build-msan -j
MSAN_OPTIONS=halt_on_error=1:exit_code=86 \
  ctest --test-dir build-msan --output-on-failure
```

CI independently exercises ASan, UBSan, MSan, and explicit `-O0`, `-O2`, and
`-O3` builds. See `docs/SANITIZER_MATRIX.md` for the exact matrix, results, and
instrumented-standard-library limitation.

## Differential fuzzing

Two opt-in Clang libFuzzer targets compare the public wrapper with the
independent Candidate A1 implementation for valid `seal` inputs and arbitrary
or malformed `open` inputs. The complete vendored call tree is instrumented
with coverage, ASan and UBSan. See `fuzz/README.md` for the input encoding,
deterministic smoke campaign and longer-run commands.

## Usage

```bash
./build/pvc-rotsymenc1 seal \
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f \
  000000000000000000000000000000000000000000000000 \
  256 "" 616263
```

Expected:

```text
ciphertext=a10b4d
tag=a16ff4b4dd13b48bab0701cd8a67f1248ebb4bf37a3146931f04e08c834d5cee
```

## Frozen upstream projects

- https://github.com/azizgokhannarin/PVC-PRF-1
- https://github.com/azizgokhannarin/PVC-MAC-0
- https://github.com/azizgokhannarin/PVC-AEAD-0

A byte-preserved Candidate A1 snapshot is vendored under `external/pvc_aead0_a1/`. Candidate A1 itself contains its pinned M1 and C1 dependencies.

## Research discipline

Passing local tests does not establish cryptographic security. The intended next step is public reproducibility and adversarial review, not further unmotivated algorithm modification.

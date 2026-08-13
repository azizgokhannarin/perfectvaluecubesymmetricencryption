# PVC-AEAD-0

PVC-AEAD-0 is an experimental nonce-based authenticated-encryption construction built as a thin composition over two frozen project components:

- **PVC-PRF-1 Candidate C1 / v0.9.0** for a nonce-and-counter keystream;
- **PVC-MAC-0 Candidate M1 / v0.2.0** for encrypt-then-MAC authentication.

The Candidate A1 construction remains byte-identical to v0.1.0 and v0.1.1:

```text
Z_i = C1_{K_enc}(StreamFrame(nonce, counter_i, tag_profile))
ciphertext = plaintext XOR Z
context = AuthContext(nonce, associated_data, tag_profile)
tag = M1_{K_mac}(context, ciphertext, tag_profile)
```

Decryption verifies the tag before deriving or returning plaintext.

## Status

**PVC-AEAD-0 Candidate A1 / v0.2.0 is a frozen experimental AEAD candidate.** It is suitable for reproducibility and external review, but it is not production-ready, has no proven bit-security claim, and has no quantified post-quantum claim.

## Critical requirements

1. `K_enc` and `K_mac` must be independently generated 256-bit keys. Equal or related keys are outside the reduction.
2. A 192-bit nonce must never repeat for any call to `seal` under the same encryption key.
3. Plaintext/ciphertext and associated-data lengths must satisfy `docs/LENGTH_AND_COUNTER_LIMITS.md`.
4. The caller must provide replay protection when the protocol requires it.
5. The library does not generate, derive, persist, or synchronize keys or nonces.

Nonce reuse reveals the XOR of equal-length plaintext prefixes. The repository includes a test and demonstration of this failure mode.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## CLI

The CLI accepts hexadecimal inputs and does not generate keys or nonces:

```bash
pvc-aead0 seal ENC_KEY MAC_KEY NONCE TAG_BITS AD PLAINTEXT
pvc-aead0 open ENC_KEY MAC_KEY NONCE AD CIPHERTEXT TAG
```

Start with `docs/CANDIDATE_FREEZE_A1.md`, `docs/SPECIFICATION.md`, `docs/FRAME_INJECTIVITY_PROOF.md`, `docs/SECURITY_REDUCTION.md`, `docs/DIFFERENTIAL_VERIFICATION.md`, and `docs/INDEPENDENT_IMPLEMENTATION.md`.

# PVC-AEAD-0 Candidate A1 / v0.2.0 Design

## Objective

PVC-AEAD-0 adds confidentiality and authenticated associated data without modifying Candidate C1 or Candidate M1 and without adding a new bespoke cryptographic primitive.

## Composition

The design uses two independently generated 256-bit keys:

- `K_enc` for C1-based counter keystream generation;
- `K_mac` for Candidate M1.

For each 32-byte block index `i`:

```text
Z_i = C1_Kenc(StreamFrame(nonce, i, tag_size))
C_i = P_i XOR Z_i
```

Authentication is encrypt-then-MAC:

```text
A = AuthContext(nonce, associated_data, tag_size)
T = M1_Kmac(A, ciphertext, tag_size)
```

Opening verifies `T` over the received nonce, associated data, and ciphertext before decrypting.

## Why encrypt-then-MAC

Encrypt-then-MAC keeps confidentiality and integrity responsibilities separate. The MAC authenticates the exact ciphertext that will be decrypted, along with the public nonce and associated data. An invalid ciphertext is rejected before plaintext is produced.

## Why no additional AEAD mixing exists

No extra cube operation, round, S-box, hash, key schedule, whitening stage, or custom tag transform is added. Such a component would create a new unanalysed primitive and destroy the clean reduction to C1 and M1.

## Key separation

The profile accepts a 512-bit key pair rather than inventing a master-key derivation mechanism. `K_enc` and `K_mac` must be independently generated. Equality, shared derivation without a separately analysed domain-separated KDF, or other correlation is outside the reduction.

The implementation intentionally does not reject equal byte strings: an equality check cannot establish statistical independence and would not detect related keys. The canonical Candidate A1 vector uses distinct role-specific values to avoid modelling misuse.

A future master-key profile would be a separately versioned construction and would require its own reduction and validation.

## Frame design

Stream and authentication inputs have distinct role bytes and injective fixed-format encodings. The formal structural argument is in `FRAME_INJECTIVITY_PROOF.md`; bounded frame enumeration remains a regression test only.

## Nonce profile

The nonce is fixed at 192 bits. The construction is deterministic for fixed keys, nonce, associated data, plaintext, and tag profile. Nonce uniqueness under `K_enc` is mandatory.

## Associated data

Associated data is authenticated but not encrypted. It does not alter the keystream, so the same nonce and plaintext under the same encryption key produce the same ciphertext even if associated data differs. The resulting tags differ because associated data is bound by M1.

## Length profile

Candidate M1's 64-bit message length limits payloads to `2^64 - 1` bytes. This bound is stricter than the available 64-bit block-counter capacity, so counter wrap cannot occur for an admissible message.

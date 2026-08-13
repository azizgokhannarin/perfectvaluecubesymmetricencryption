# PVC-RotSymEnc-1 Normative Specification — v0.1.0-draft

## 1. Scope

PVC-RotSymEnc-1 is a public algorithm profile for nonce-based authenticated symmetric encryption. Its cryptographic behavior is **normatively identical** to PVC-AEAD-0 Candidate A1 / v0.2.0.

No transformation in this document may alter Candidate A1 ciphertext or tag bytes.

## 2. Inputs

A sealing operation takes:

- `K_enc`: exactly 32 bytes;
- `K_mac`: exactly 32 bytes;
- `N`: exactly 24 bytes;
- `AD`: associated data satisfying Candidate A1 length limits;
- `P`: plaintext satisfying Candidate A1 length limits;
- `t`: tag size, exactly 16, 24, or 32 bytes.

`K_enc` and `K_mac` SHALL be generated independently. Equal or related role keys are outside the conditional security reduction.

`N` SHALL NOT repeat for any `seal` invocation under the same `K_enc`.

## 3. Seal

PVC-RotSymEnc-1 `seal` SHALL invoke the byte-exact Candidate A1 sealing construction:

```text
for counter i = 0,1,...:
    Z_i = C1_Kenc(StreamFrame(N, i, t))
C = P XOR first_|P|_bytes(Z_0 || Z_1 || ...)
A = AuthContext(N, AD, t)
T = M1_Kmac(A, C, t)
return (C,T)
```

`StreamFrame`, `AuthContext`, C1, M1, tag-profile binding, counter encoding, length limits, and all other cryptographic details are exactly those frozen by Candidate A1 / v0.2.0.

## 4. Open

`open(K_enc,K_mac,N,AD,C,T)` SHALL:

1. reject unsupported tag lengths;
2. construct the Candidate A1 authentication context;
3. verify the M1 tag over the complete ciphertext;
4. return failure without deriving or releasing plaintext if authentication fails;
5. only after successful authentication, apply the Candidate A1 keystream to recover plaintext.

## 5. Tag profiles

Supported tag sizes are 128, 192, and 256 bits. Tag size is domain-bound in the frozen underlying frames. A tag from one profile is not a valid prefix form of another profile.

## 6. Key profile

PVC-RotSymEnc-1 deliberately defines two externally supplied keys rather than a master key. No KDF is part of this specification.

## 7. Nonce profile

The nonce is exactly 192 bits. The construction is not nonce-misuse resistant. Nonce reuse under the same encryption key repeats the C1-derived keystream for equal counter positions.

## 8. Maximum lengths

The frozen Candidate A1 limits apply. Plaintext and ciphertext are at most `2^64 - 1` bytes. The authentication-context constraints additionally bound associated data as specified by `external/pvc_aead0_a1/docs/LENGTH_AND_COUNTER_LIMITS.md`.

Within that admissible message domain, 32-byte stream blocks require at most `2^59` counters, so the frozen 64-bit counter does not wrap.

## 9. Canonical vector

```text
K_enc = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
K_mac = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
N     = 000000000000000000000000000000000000000000000000
AD    = empty
P     = 616263
t     = 256
C     = a10b4d
T     = a16ff4b4dd13b48bab0701cd8a67f1248ebb4bf37a3146931f04e08c834d5cee
```

## 10. Conformance

An implementation conforms only if it reproduces Candidate A1 outputs exactly. The wrapper must not introduce alternate framing, padding, key derivation, nonce derivation, tag encoding, or cryptographic mixing.

## 11. Status

This is a draft public profile over a frozen experimental AEAD candidate. It does not claim proven confidentiality, proven integrity, a specific classical security level, a quantified post-quantum security level, side-channel resistance, fault resistance, or production readiness.

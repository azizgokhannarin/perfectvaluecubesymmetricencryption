# PVC-AEAD-0 Candidate A1 / v0.2.0 Bit-Exact Specification

The cryptographic construction bytes are unchanged from v0.1.0. Candidate A1 freezes the same cryptographic bytes after independent reimplementation and differential verification. No stream, authentication, truncation, nonce, counter, or wire-format rule changed from v0.1.1.

## 1. Parameters

| Parameter | Value |
|---|---:|
| Encryption key `K_enc` | 32 bytes |
| Authentication key `K_mac` | 32 bytes |
| Nonce `N` | 24 bytes |
| C1 output / stream block | 32 bytes |
| Supported tags | 16, 24, or 32 bytes |
| Counter | unsigned 64-bit big-endian |

`K_enc` and `K_mac` are separate API values and **must be independently generated**. Exact equality or any related-key derivation is outside the security reduction. No master-key derivation is defined by this profile.

All byte strings are interpreted literally. No text encoding, implicit terminator, padding, or normalization is applied.

## 2. Stream-frame encoding

For tag length `t` bytes, nonce `N`, and counter `i`, define:

```text
StreamFrame(N,i,t) =
    "PVC-AEAD-0"             // 10 ASCII bytes
 || 00                       // separator
 || 01                       // frame version
 || 53                       // role: stream ('S')
 || C1                       // PVC-PRF-1 Candidate C1 profile
 || BYTE(t)                  // 10, 18, or 20 hexadecimal
 || 00                       // reserved
 || N                        // exactly 24 bytes
 || U64BE(i)                 // exactly 8 bytes
```

The total length is exactly 48 bytes. Counters start at zero and increase by one for each 32-byte plaintext block.

## 3. Keystream and encryption

For block index `i`:

```text
Z_i = PVC-PRF-1-C1(K_enc, StreamFrame(N,i,t))
C_i = P_i XOR prefix_len(P_i)(Z_i)
```

Concatenate all `C_i` values. Ciphertext length equals plaintext length. Empty plaintext produces empty ciphertext and still receives a tag.

## 4. Authentication-context encoding

```text
AuthContext(N,AD,t) =
    "PVC-AEAD-0"             // 10 ASCII bytes
 || 00                       // separator
 || 01                       // frame version
 || 41                       // role: authentication ('A')
 || C1                       // encryption primitive profile
 || D1                       // PVC-MAC-0 Candidate M1 profile
 || BYTE(t)                  // tag length in bytes
 || 00                       // reserved
 || N                        // exactly 24 bytes
 || U64BE(len(AD))           // exactly 8 bytes
 || AD
```

The fixed portion is 49 bytes. The complete authentication context must fit Candidate M1's unsigned 64-bit context-length field.

## 5. Authentication

Let `M1` be the frozen Candidate M1 construction:

```text
T = PVC-MAC-0-M1(K_mac, AuthContext(N,AD,t), C, t)
```

Candidate M1 injectively frames its context, ciphertext message, and tag length. Therefore nonce, associated data, ciphertext length/content, and tag profile are all authenticated.

## 6. Sealing

```text
Seal(K_enc,K_mac,N,AD,P,t):
    require independent key roles
    require admissible lengths
    C = Encrypt(K_enc,N,P,t)
    A = AuthContext(N,AD,t)
    T = M1(K_mac,A,C,t)
    return (C,T)
```

The implementation accepts two explicit keys but cannot prove that they were independently generated. That requirement belongs to key management.

## 7. Opening

```text
Open(K_enc,K_mac,N,AD,C,T):
    reject unless len(T) is 16, 24, or 32
    require admissible lengths
    t = len(T)
    A = AuthContext(N,AD,t)
    reject unless M1.Verify(K_mac,A,C,T)
    P = Encrypt(K_enc,N,C,t)
    return P
```

Tag verification occurs before keystream application or plaintext return.

## 8. Injectivity and domain separation

`StreamFrame` is injective in `(N,i,t)`. `AuthContext` is injective in `(N,AD,t)`. The two frame families are disjoint because their fixed role bytes differ (`53` versus `41`). Candidate M1 then injectively binds `(AuthContext,C,t)`.

The complete structural argument is in `FRAME_INJECTIVITY_PROOF.md`.

## 9. Nonce rule

A nonce must never repeat for any sealing operation under the same encryption key. The operational profile uses the stronger rule that nonces remain unique regardless of tag size. Reuse exposes XOR relations between plaintexts and is outside the security reduction.

## 10. Length and counter limits

Normative limits are:

```text
len(P), len(C) <= 2^64 - 1 bytes
len(AuthContext) <= 2^64 - 1 bytes
len(AD) <= 2^64 - 1 - 49 bytes
```

At the maximum admissible payload length, at most `2^59` stream blocks are used, with counters `0` through `2^59 - 1`. Counter wrap is therefore unreachable.

Implementations may impose smaller `size_t`, container, memory, or protocol limits. See `LENGTH_AND_COUNTER_LIMITS.md`.

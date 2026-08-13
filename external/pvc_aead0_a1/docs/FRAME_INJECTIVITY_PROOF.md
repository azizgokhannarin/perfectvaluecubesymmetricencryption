# PVC-AEAD-0 Candidate A1 / v0.2.0 Frame Injectivity Proof

This document gives the structural argument used by the security reduction. The bounded framing audit is a regression check; it is not the basis of this proof.

## 1. Stream frame

For an admissible tuple `(N,i,t)`, the stream frame is:

```text
magic[10] || separator[1] || version[1] || role[1] || C1[1]
|| tag_bytes[1] || reserved[1] || nonce[24] || U64BE(counter)[8]
```

Its total length is 48 bytes and every variable field has a fixed offset and width.

Assume:

```text
StreamFrame(N1,i1,t1) = StreamFrame(N2,i2,t2).
```

Equality at the tag-profile byte gives `t1 = t2`. Equality of bytes 16 through 39 gives `N1 = N2`. Equality of the final eight bytes gives `U64BE(i1) = U64BE(i2)`. Big-endian encoding of a 64-bit integer is one-to-one, so `i1 = i2`.

Therefore `StreamFrame` is injective in `(N,i,t)`.

## 2. Authentication context

For an admissible tuple `(N,AD,t)`, the authentication context is:

```text
magic[10] || separator[1] || version[1] || role[1] || C1[1]
|| M1[1] || tag_bytes[1] || reserved[1] || nonce[24]
|| U64BE(len(AD))[8] || AD
```

Assume:

```text
AuthContext(N1,AD1,t1) = AuthContext(N2,AD2,t2).
```

Equality at the tag-profile byte gives `t1 = t2`. Equality of the fixed nonce field gives `N1 = N2`. Equality of the eight-byte length field gives `len(AD1) = len(AD2)`. The remaining suffix has exactly that encoded length, so equality of the complete byte strings gives `AD1 = AD2`.

Therefore `AuthContext` is injective in `(N,AD,t)`.

## 3. Separation of frame families

The role byte is at the same fixed offset in both frame families:

```text
stream role:          0x53
 authentication role: 0x41
```

Thus no stream frame can equal an authentication-context frame. Their lengths also differ for empty associated data: 48 bytes versus 49 bytes.

## 4. Complete authenticated tuple

Candidate M1 injectively frames:

```text
(context, message, tag_length)
```

PVC-AEAD-0 supplies:

```text
context = AuthContext(N,AD,t)
message = ciphertext C
```

Combining M1's frozen injectivity proof with Section 2 gives an injective authenticated encoding of:

```text
(N, AD, C, t)
```

within the documented length limits.

## 5. Counter uniqueness under the nonce contract

Within one message, block counters are `0,1,...,b-1`, so no two blocks use the same counter. Across sealing calls, the nonce contract forbids reuse under one encryption key. By StreamFrame injectivity, all stream inputs under one encryption key are therefore distinct in the nonce-respecting model.

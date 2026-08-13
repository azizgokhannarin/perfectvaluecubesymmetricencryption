# PVC-MAC-0 Candidate M1 / v0.2.0 Bit-Exact Specification

The construction bytes are unchanged from v0.1.0 and v0.1.1.

## 1. Inputs

- `K`: exactly 32 bytes.
- `C`: context byte string, length representable as unsigned 64-bit integer.
- `M`: message byte string, length representable as unsigned 64-bit integer.
- `t`: tag length in bytes, exactly one of `16`, `24`, or `32`.

All byte strings are binary. Embedded zero bytes are preserved.

## 2. Integer encoding

`U64BE(x)` is the eight-byte, unsigned, big-endian encoding of `x`.

## 3. Canonical frame

The C1 input is the concatenation:

```text
Offset  Length  Value
0       9       ASCII "PVC-MAC-0"
9       1       00
10      1       01              # frame version
11      1       C1              # PVC-PRF-1 Candidate C1 profile
12      1       t               # 10, 18, or 20 in hexadecimal
13      1       00              # reserved
14      8       U64BE(len(C))
22      8       U64BE(len(M))
30      |C|     C
30+|C|  |M|     M
```

Therefore:

```text
Frame(C,M,t) =
    50 56 43 2D 4D 41 43 2D 30 ||
    00 || 01 || C1 || byte(t) || 00 ||
    U64BE(len(C)) || U64BE(len(M)) || C || M
```

The explicit lengths make the mapping from `(C,M,t)` to the frame injective. The structural argument is in `FRAME_INJECTIVITY_PROOF.md`.

## 4. Primitive evaluation

Evaluate the frozen default-profile function:

```text
Y = PVC-PRF-1-C1-v0.9.0(K, Frame(C,M,t))
```

This is the full keyed forward pass, transcript-derived return pass, and controller-bound finalization defined by the vendored C1 specification. All C1 default parameters remain unchanged.

## 5. Tag

```text
Tag_t(K,C,M) = Y[0 .. t-1]
```

Only the first `t` bytes are transmitted. Because `t` is inside the frame, tags for different supported lengths belong to distinct domains.

## 6. Verification

1. Reject unless the supplied tag length is 16, 24, or 32 bytes.
2. Recompute `Tag_t(K,C,M)` for that exact supplied length.
3. XOR all corresponding bytes and OR the differences into one accumulator.
4. Accept iff the accumulator is zero.

The comparison loop must not exit early based on tag byte contents. Unsupported public lengths may be rejected before C1 evaluation. Complete API and error semantics are in `API_BEHAVIOR.md`.

## 7. Key-use rule

A PVC-MAC-0 key must be uniformly distributed over 32 bytes and dedicated to this construction. Reusing the same key for raw C1 access or another protocol is outside the Candidate M1 security model.

## 8. Conditional security rationale

The PRF-as-MAC reduction, framed-input subdomain assumption, and limitations are stated in `SECURITY_REDUCTION.md`. The reduction is conditional on C1 behaving as a secure PRF; it is not a proof that C1 has that property.

## 9. Candidate identity

The exact Candidate M1 freeze scope and change rule are in `CANDIDATE_FREEZE_M1.md`.

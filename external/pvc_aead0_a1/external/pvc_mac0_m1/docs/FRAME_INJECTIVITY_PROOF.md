# PVC-MAC-0 Frame Injectivity Argument

## Statement

For the supported input domain, the canonical encoder

```text
Frame(C, M, t)
```

is injective in the tuple `(C, M, t)`.

The supported domain consists of binary context and message strings whose lengths are representable by an unsigned 64-bit integer, and `t` in `{16, 24, 32}` bytes.

## Argument

Assume that two canonical frames are byte-for-byte equal:

```text
Frame(C1, M1, t1) = Frame(C2, M2, t2).
```

The fixed magic, separator, frame-version, primitive-profile, and reserved fields occupy identical fixed offsets in every frame. The tag-length byte is also at a fixed offset. Equality of the frames therefore implies:

```text
t1 = t2.
```

The next two fields are fixed-width eight-byte unsigned big-endian integers. Because `U64BE` is a one-to-one encoding over unsigned 64-bit values, equality of those fields implies:

```text
len(C1) = len(C2) = c
len(M1) = len(M2) = m.
```

After the 30-byte header, the parser consumes exactly `c` bytes as the context and exactly `m` bytes as the message. Equality of the complete frames therefore implies equality of the corresponding byte ranges:

```text
C1 = C2
M1 = M2.
```

Hence:

```text
(C1, M1, t1) = (C2, M2, t2),
```

which proves injectivity on the supported domain.

## Consequences

- Context/message boundary changes cannot alias.
- Embedded zero bytes do not terminate either field.
- Appending bytes changes the encoded message length and frame contents.
- The 128-, 192-, and 256-bit tag profiles are distinct PRF input domains.

The bounded framing audit is an implementation regression test. It is not the basis of this argument; injectivity follows structurally from the fixed-width length fields and canonical field order.

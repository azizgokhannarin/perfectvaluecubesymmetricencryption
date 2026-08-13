# PVC-MAC-0 API and Error Semantics

## Supported tag lengths

The public API supports exactly 16, 24, and 32-byte tags.

- `compute_tag` accepts a typed `TagSize` value.
- `tag_size_from_bytes` throws `std::invalid_argument` for every other length.
- `verify_tag` returns `false` immediately for every unsupported supplied-tag length.

Tag length is public protocol metadata. Early rejection of an unsupported public length is outside the content-independent comparison claim.

## Verification timing claim

For a supported tag length, `verify_tag`:

1. recomputes the corresponding profile-specific full C1 output,
2. examines every supplied tag byte,
3. accumulates all byte differences with XOR/OR,
4. returns only after the complete comparison loop.

No claim is made that the complete MAC computation is constant-time. C1 uses data-dependent memory access.

## Length and allocation failures

The canonical frame stores context and message lengths as unsigned 64-bit integers.

- On a platform where `size_t` is wider than 64 bits, a context or message longer than `UINT64_MAX` causes `std::length_error` before framing.
- Any `size_t` overflow in `30 + context_length + message_length` also causes `std::length_error` before allocation.
- Ordinary allocation failure may propagate as `std::bad_alloc`.

These checks depend only on public input lengths, not on the key or tag contents. A network or protocol wrapper should translate exceptions into one generic input-size failure and should impose a substantially smaller application-level maximum message size.

## Binary input behavior

Contexts and messages are byte spans. Embedded zero bytes are preserved and have no terminator semantics.

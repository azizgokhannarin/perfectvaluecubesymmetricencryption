# PVC-AEAD-0 Candidate A1 / v0.2.0 Length and Counter Limits

## Normative mathematical limits

PVC-AEAD-0 uses 64-bit length fields in Candidate M1 and a 64-bit stream counter.

| Quantity | Maximum |
|---|---:|
| Plaintext length | `2^64 - 1` bytes |
| Ciphertext length | `2^64 - 1` bytes |
| Encoded authentication-context length | `2^64 - 1` bytes |
| Associated-data length | `2^64 - 1 - 49` bytes |
| Counter value | `2^64 - 1` |

The 49-byte subtraction is the fixed size of `AuthContext` before associated data.

## Why the counter cannot wrap

A stream block encrypts at most 32 bytes. The maximum accepted payload length is `2^64 - 1` bytes because Candidate M1 encodes the ciphertext length in `U64BE`.

Therefore the maximum number of stream blocks is:

```text
ceil((2^64 - 1) / 32) = 2^59
```

The counters used are consequently:

```text
0 ... 2^59 - 1
```

This is strictly inside the 64-bit counter domain. Counter wrap is unreachable for every admissible PVC-AEAD-0 message.

## Implementation behavior

`seal` validates that plaintext length fits the unsigned 64-bit framing limit before encryption. `open` validates ciphertext length before authentication/decryption processing. Authentication-context construction rejects associated data that would make the complete context exceed the Candidate M1 64-bit context-length field.

The implementation also requires all vector allocations and the complete M1 frame to fit the platform's `size_t` and allocator limits. Those practical limits will normally be much smaller than the mathematical limits above. Violations are reported with `std::length_error`; allocation failures propagate normally.

No attempt is made to process partial data after a length failure.

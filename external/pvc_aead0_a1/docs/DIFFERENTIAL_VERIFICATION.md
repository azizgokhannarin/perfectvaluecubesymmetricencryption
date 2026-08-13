# PVC-AEAD-0 Candidate A1 Differential Verification

## Implementations

- Canonical AEAD wrapper: `src/aead.cpp`
- Independent specification wrapper: `independent/cpp_spec/src/aead.cpp`
- Canonical MAC dependency: `external/pvc_mac0_m1/src/mac.cpp`
- Independent MAC dependency: `external/pvc_mac0_m1/independent/cpp_spec/src/mac.cpp`
- Shared primitive: frozen PVC-PRF-1 Candidate C1 / v0.9.0

## Retained known-answer corpus

Both AEAD wrappers reproduce all 48 canonical vectors in:

```text
vectors/PVC_AEAD0_VECTORS_0.1.0.csv
```

The corpus intentionally retains its original filename because the
construction bytes have not changed.

## Wide differential corpus

Candidate A1 retains 4,096 deterministic binary cases:

```text
vectors/PVC_AEAD0_DIFFERENTIAL_A1.csv
```

The generator uses fixed SplitMix64 seed `0x5056434145414441` and is
reproducibility tooling, not a cryptographic random generator.

Coverage includes:

- all 128-, 192-, and 256-bit tag profiles in rotation;
- independent arbitrary 256-bit encryption and authentication keys;
- random, all-zero, and all-`ff` 192-bit nonces;
- empty and binary associated data and plaintext;
- embedded `00` and `ff` values;
- ordinary lengths plus explicit boundaries around 8, 16, 24, 32, 48, 64,
  96, 128, 256, 512, and 1,024 bytes;
- stream-counter encoding at `0`, `1`, `255`, `2^32-1`, `2^32`,
  `2^63-1`, and `2^64-1` in 133 selected cases.

For every one of the 4,096 tuples, the campaign compares:

1. every used StreamFrame byte string;
2. used keystream bytes derived as `plaintext XOR ciphertext`;
3. complete ciphertext;
4. complete AuthContext byte string;
5. returned tag;
6. canonical opening of the independent output;
7. independent opening of the canonical output;
8. recovered plaintext.

Additional rejection budgets are:

```text
one-bit tag changes:       512 cases, both implementations
wrong nonce:                64 cases, both implementations
wrong associated data:     64 cases, both implementations
wrong ciphertext:          63 cases, both implementations
```

Result:

```text
4096/4096 differential tuples matched
stream-frame mismatches:       0
used-keystream mismatches:     0
ciphertext mismatches:         0
auth-context mismatches:       0
tag mismatches:                0
cross-open failures:           0
unexpected tamper accepts:     0
```

The corpus was regenerated twice from the clean source tree and compared
byte-for-byte.

## Interpretation and limitation

This campaign establishes agreement between two AEAD composition paths and two
MAC wrapper paths. Both paths still share Candidate C1. It is therefore an
interoperability and specification test, not an independent cryptanalysis or
implementation of the underlying PRF.

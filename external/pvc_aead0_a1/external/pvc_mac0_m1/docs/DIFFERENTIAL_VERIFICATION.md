# PVC-MAC-0 Candidate M1 Differential Verification

## Implementations

- Canonical wrapper: `src/mac.cpp`
- Independent specification wrapper: `independent/cpp_spec/src/mac.cpp`
- Shared frozen primitive: vendored PVC-PRF-1 Candidate C1 / v0.9.0

## Retained known-answer corpus

The independent implementation reproduced all 48 canonical vectors in:

```text
vectors/PVC_MAC0_VECTORS_0.1.0.csv
SHA-256: 482b36274d940c1279a69b47c9254bbcfb1fb1c821c2dfacce39441fb9cca1ea
```

## Wide differential corpus

Candidate M1 retains 4,096 deterministic binary cases:

```text
vectors/PVC_MAC0_DIFFERENTIAL_M1.csv
SHA-256: 941fddaf40f82bcf7929d7be1a9f396676bd75b1e7496e9c2594e6aa408078d6
```

The generator uses a fixed SplitMix64 seed `0x5056434D41434D31` and is only reproducibility tooling, not a cryptographic RNG.

Coverage includes:

- all three tag profiles in rotation;
- arbitrary 256-bit keys;
- empty and binary contexts/messages;
- embedded `00` and `ff` bytes;
- regular lengths plus explicit boundaries around 8, 16, 24, 30, 32, 64, 128, 256, 512, and 1,024 bytes.

For every tuple the campaign compared:

1. canonical frame bytes;
2. independent frame bytes;
3. full 256-bit C1 output;
4. returned truncated tag;
5. canonical verification of the independent tag;
6. independent verification of the canonical tag;
7. rejection of a deterministic one-bit tag modification by both implementations.

Result:

```text
4096/4096 cases matched
frame mismatches:       0
full-output mismatches: 0
tag mismatches:         0
valid-tag rejects:      0
modified-tag accepts:   0
```

## Bounded integration/API-misuse audit

The closure test additionally checks:

- wrong key, context, and message rejection;
- every byte position of 16-, 24-, and 32-byte tags after modification;
- `(context="ab", message="c")` versus `(context="a", message="bc")`;
- empty-field repartitioning;
- zero-byte extension;
- invalid public tag lengths;
- rejection of 256-profile prefixes as 128- or 192-profile tags.

## Interpretation and limitation

This campaign is evidence that the written specification and two wrapper implementations agree. It is not an independent implementation of C1 and is not a cryptanalytic test of C1's pseudorandomness on the framed-input subdomain.

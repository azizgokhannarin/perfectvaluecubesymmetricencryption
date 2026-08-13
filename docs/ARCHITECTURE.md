# Architecture

PVC-RotSymEnc-1 is an umbrella profile, not a new cryptographic layer.

```text
PVC-PRF-1 Candidate C1 / v0.9.0
    fixed 256-bit keyed output
                |
                v
PVC-MAC-0 Candidate M1 / v0.2.0
    injective PRF-as-MAC frame
                |
                v
PVC-AEAD-0 Candidate A1 / v0.2.0
    C1 nonce+counter stream + M1 Encrypt-then-MAC
                |
                v
PVC-RotSymEnc-1 / v0.1.0-draft
    public name, API profile, conformance and review package
```

The final arrow adds no cryptographic operation. `src/symmetric_encryption.cpp` is intentionally a narrow adapter to Candidate A1.

This separation is deliberate: weaknesses discovered in C1, M1, or A1 remain attributable to the correct layer, while API/profile problems can be fixed without silently mutating the cryptographic candidate.

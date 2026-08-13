# PVC-MAC-0 v0.2.0 — Candidate M1 Release Notes

This release freezes the unchanged v0.1.x construction as **PVC-MAC-0 Candidate M1**.

Added:

- a second MAC-wrapper implementation written from the bit-exact specification;
- independent reproduction of the retained 48-vector corpus;
- a 4,096-case binary differential corpus covering frame, full C1 output, tag, and verification;
- bounded integration/API-misuse auditing;
- explicit framed-input subdomain limitation in the security claims and reduction;
- Candidate M1 freeze document and reproducibility script.

Unchanged cryptographic behavior:

- `src/mac.cpp` construction;
- canonical frame bytes;
- C1 dependency and parameters;
- 128/192/256-bit tag rules;
- existing KAT values and 48-vector corpus.

Candidate M1 remains experimental research software and must not be used to protect production data.

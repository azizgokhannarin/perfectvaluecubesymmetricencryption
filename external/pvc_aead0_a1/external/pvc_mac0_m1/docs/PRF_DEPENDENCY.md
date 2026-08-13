# PVC-PRF-1 C1 Dependency — Candidate M1

PVC-MAC-0 Candidate M1 / v0.2.0 vendors only the source files required to evaluate the frozen PVC-PRF-1 Candidate C1 / v0.9.0 primitive.

Source archive used for this snapshot:

```text
perfectvaluecubeprf1-0.9.0-publication-prep.zip
SHA-256: bfbc74ecabdd59ed5430f1fcbf7bfe9db048607fd47320ee0923c3319c2786bb
```

The publication-preparation archive changed documentation only; its algorithm sources were verified as byte-identical to Candidate C1 v0.9.0.

The vendored directory contains:

- all `include/pvc1/*.hpp` files,
- all six C1 implementation `.cpp` files,
- upstream Apache-2.0 license,
- upstream version and frozen specification documents.

`external/pvc_prf1_c1/SOURCE_MANIFEST.SHA256` fingerprints every vendored file. Neither the canonical nor independent MAC wrapper may patch these files.

The two MAC wrappers share this dependency. Their independence claim is limited to the MAC composition layer and does not imply two independent implementations of C1.

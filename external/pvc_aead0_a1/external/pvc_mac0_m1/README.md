# Perfect Value Cube MAC

**PVC-MAC-0 Candidate M1 / v0.2.0** is a frozen experimental message-authentication construction built on the frozen **PVC-PRF-1 Candidate C1 / v0.9.0** primitive.

> Research software only. Do not use PVC-MAC-0 to protect production data, credentials, firmware, financial transactions, or safety-critical systems.

## Construction

```text
Tag_t(K,C,M) = Prefix_t(C1_K(Frame(C,M,t)))
```

The canonical injective frame binds:

- the MAC construction identifier,
- frame version,
- frozen primitive profile (`C1`),
- requested tag length,
- context length and context,
- message length and message.

The supported tag sizes are 128, 192, and 256 bits. Tag length is domain-bound: a 128-bit tag is not defined as the prefix of the 256-bit profile output.

## Candidate M1 evidence

- structural frame-injectivity proof;
- conditional PRF-as-MAC reduction;
- pinned and unmodified C1 snapshot;
- canonical and independent wrapper implementations;
- 48/48 retained KAT reproduction by both wrappers;
- 4,096/4,096 binary differential cases;
- bounded integration/API-misuse audit;
- GCC, Clang, ASan, and UBSan verification.

The independent wrapper shares only the frozen C1 primitive. It independently implements framing, tag-size handling, truncation, and verification.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Example:

```bash
./build/pvc-mac0 \
  --key-hex 0000000000000000000000000000000000000000000000000000000000000000 \
  --text abc \
  --tag-bytes 32
```

Full reproducibility campaign:

```bash
./scripts/run_candidate_m1_campaign.sh
```

## Review map

- bit-exact specification: `docs/SPECIFICATION.md`
- candidate freeze: `docs/CANDIDATE_FREEZE_M1.md`
- frozen-file manifest: `CANDIDATE_MANIFEST.SHA256`
- frame proof: `docs/FRAME_INJECTIVITY_PROOF.md`
- conditional reduction: `docs/SECURITY_REDUCTION.md`
- security boundaries: `docs/SECURITY_CLAIMS.md`
- independent implementation: `docs/INDEPENDENT_IMPLEMENTATION.md`
- differential verification: `docs/DIFFERENTIAL_VERIFICATION.md`
- dependency provenance: `docs/PRF_DEPENDENCY.md`
- API/error semantics: `docs/API_BEHAVIOR.md`
- threat model: `docs/THREAT_MODEL.md`

Candidate M1 does not claim proven unforgeability, production readiness, standardization readiness, a dedicated cryptanalytic campaign on the exact framed-input distribution, or a quantified post-quantum security level.

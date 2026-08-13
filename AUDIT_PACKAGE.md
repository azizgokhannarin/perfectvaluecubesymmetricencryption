# Audit Package

Recommended review order:

1. `README.md`
2. `SPECIFICATION.md`
3. `docs/ARCHITECTURE.md`
4. `docs/SECURITY_TARGET.md`
5. `docs/COMPONENT_PROVENANCE.md`
6. `external/pvc_aead0_a1/docs/CANDIDATE_FREEZE_A1.md`
7. `external/pvc_aead0_a1/docs/SECURITY_REDUCTION.md`
8. `external/pvc_aead0_a1/docs/FRAME_INJECTIVITY_PROOF.md`
9. `external/pvc_aead0_a1/docs/DIFFERENTIAL_VERIFICATION.md`
10. `CRYPTANALYSIS_CHALLENGE.md`
11. `test-vectors/`

The public wrapper intentionally contains no independent cryptographic transformation beyond Candidate A1. Auditors should treat any output drift as a conformance failure.

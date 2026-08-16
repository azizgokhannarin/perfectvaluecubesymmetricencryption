# Audit Package

Review snapshot: `v0.1.0-draft-review.1`

This package is organized for independent falsification. It does not assert
that PVC-RotSymEnc-1 or its frozen dependencies are secure.

## Fast review order

1. `PUBLIC_REVIEW.md` - scope, known findings, and requested attacks.
2. `SPECIFICATION.md` - normative public profile.
3. `docs/SECURITY_TARGET.md` - conditional target and explicit non-claims.
4. `docs/ARCHITECTURE.md` - C1 to M1 to A1 to RotSymEnc composition.
5. `docs/COMPONENT_PROVENANCE.md` - exact frozen dependency chain.
6. `CRYPTANALYSIS_CHALLENGE.md` - stable finding classes and reporting rules.
7. `docs/ATTACK_LOG.md` - retained positive and bounded-negative results.
8. `docs/REPRODUCIBILITY.md` - one-command campaign and limitations.
9. `test-vectors/` - canonical and differential artifacts.

## Underlying construction review

Reviewers analyzing the inherited cryptographic construction should continue
with:

1. `external/pvc_aead0_a1/docs/CANDIDATE_FREEZE_A1.md`;
2. `external/pvc_aead0_a1/docs/SECURITY_REDUCTION.md`;
3. `external/pvc_aead0_a1/docs/FRAME_INJECTIVITY_PROOF.md`;
4. `external/pvc_aead0_a1/docs/DIFFERENTIAL_VERIFICATION.md`;
5. the nested M1 and C1 specifications, attack records, and manifests.

## Integrity and baseline checks

```bash
sha256sum --check --quiet SOURCE_MANIFEST.SHA256
sha256sum --check --quiet PROFILE_MANIFEST.SHA256
./scripts/verify_candidate_a1_manifest.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The public wrapper intentionally contains no independent cryptographic transformation beyond Candidate A1. Auditors should treat any output drift as a conformance failure.

# PVC-MAC-0 Candidate M1 / v0.2.0 Audit Package

Minimum review path:

1. Read `docs/SPECIFICATION.md` and `docs/CANDIDATE_FREEZE_M1.md`.
2. Check the structural frame argument in `docs/FRAME_INJECTIVITY_PROOF.md`.
3. Check the assumptions and limitations in `docs/SECURITY_REDUCTION.md` and `docs/SECURITY_CLAIMS.md`.
4. Review the independence boundary in `docs/INDEPENDENT_IMPLEMENTATION.md`.
5. Review the comparison surface in `docs/DIFFERENTIAL_VERIFICATION.md`.
6. Verify `CANDIDATE_MANIFEST.SHA256`, `external/pvc_prf1_c1/SOURCE_MANIFEST.SHA256`, and root `SOURCE_MANIFEST.SHA256`.
7. Build with GCC or Clang and run all CTest entries.
8. Regenerate both vector corpora and compare byte-for-byte.
9. Re-run the framing, avalanche, and integration/API-misuse checks.

Canonical commands:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure

./build/pvc-mac0-vector-generator --output /tmp/kat.csv --count 48
cmp /tmp/kat.csv vectors/PVC_MAC0_VECTORS_0.1.0.csv

./build/pvc-mac0-independent-differential \
  --count 4096 \
  --write-corpus /tmp/differential.csv
cmp /tmp/differential.csv vectors/PVC_MAC0_DIFFERENTIAL_M1.csv

./build/pvc-mac0-integration-misuse-audit
./build/pvc-mac0-framing-audit
./build/pvc-mac0-avalanche-probe
```

Or run:

```bash
./scripts/run_candidate_m1_campaign.sh
```

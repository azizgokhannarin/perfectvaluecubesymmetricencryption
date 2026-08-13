#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${1:-$ROOT/build-campaign-0.2.0}"
TMP_KAT="$(mktemp)"
TMP_DIFF="$(mktemp)"
trap 'rm -f "$TMP_KAT" "$TMP_DIFF"' EXIT

cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release \
  -DPVCAEAD0_DIFFERENTIAL_CASES=4096
cmake --build "$BUILD" -j
ctest --test-dir "$BUILD" --output-on-failure

"$BUILD/pvc-aead0-vector-generator" "$TMP_KAT"
cmp "$ROOT/vectors/PVC_AEAD0_VECTORS_0.1.0.csv" "$TMP_KAT"

"$BUILD/pvc-aead0-independent-differential" --count 4096 --write-corpus "$TMP_DIFF"
cmp "$ROOT/vectors/PVC_AEAD0_DIFFERENTIAL_A1.csv" "$TMP_DIFF"

"$BUILD/pvc-aead0-framing-audit"
"$BUILD/pvc-aead0-composition-audit"
"$BUILD/pvc-aead0-nonce-reuse-demo"

sha256sum -c "$ROOT/DEPENDENCY_MANIFEST.SHA256"
sha256sum -c "$ROOT/CANDIDATE_MANIFEST.SHA256"

echo "PVC-AEAD-0 Candidate A1 / v0.2.0 campaign completed"

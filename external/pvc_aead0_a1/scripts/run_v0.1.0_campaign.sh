#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${1:-$ROOT/build-campaign}"

cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD" -j
ctest --test-dir "$BUILD" --output-on-failure

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
"$BUILD/pvc-aead0-vector-generator" "$TMP"
cmp "$ROOT/vectors/PVC_AEAD0_VECTORS_0.1.0.csv" "$TMP"
"$BUILD/pvc-aead0-framing-audit"
"$BUILD/pvc-aead0-composition-audit"
"$BUILD/pvc-aead0-nonce-reuse-demo"

echo "PVC-AEAD-0 v0.1.0 campaign completed"

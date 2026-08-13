#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${1:-$ROOT/build-campaign-0.1.1}"

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

"$BUILD/pvc-aead0" seal \
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f \
  000000000000000000000000000000000000000000000000 \
  256 '' 616263

echo "PVC-AEAD-0 v0.1.1 campaign completed"

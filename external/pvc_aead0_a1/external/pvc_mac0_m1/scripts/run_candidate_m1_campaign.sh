#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${1:-$root/build-candidate-m1}"
out="$root/results-0.2.0"

mkdir -p "$out"

cmake -S "$root" -B "$build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build" -j
ctest --test-dir "$build" --output-on-failure | tee "$out/CTEST.txt"

"$build/pvc-mac0-vector-generator" \
  --output "$out/PVC_MAC0_VECTORS_REGENERATED.csv" --count 48
cmp "$out/PVC_MAC0_VECTORS_REGENERATED.csv" \
    "$root/vectors/PVC_MAC0_VECTORS_0.1.0.csv"

tmp_differential="$(mktemp /tmp/pvcmac-m1-differential.XXXXXX.csv)"
trap 'rm -f "$tmp_differential"' EXIT
"$build/pvc-mac0-independent-differential" \
  --count 4096 \
  --write-corpus "$tmp_differential" \
  | tee "$out/INDEPENDENT_DIFFERENTIAL.txt"
cmp "$tmp_differential" "$root/vectors/PVC_MAC0_DIFFERENTIAL_M1.csv"
echo "differential_corpus=byte-identical" | tee "$out/DIFFERENTIAL_CORPUS_COMPARE.txt"

"$build/pvc-mac0-integration-misuse-audit" \
  | tee "$out/INTEGRATION_MISUSE_AUDIT.txt"
"$build/pvc-mac0-framing-audit" \
  | tee "$out/FRAMING_AUDIT_REGENERATED.txt"
"$build/pvc-mac0-avalanche-probe" \
  | tee "$out/MESSAGE_AVALANCHE_256_REGENERATED.txt"

(
    cd "$root/external/pvc_prf1_c1"
    sha256sum -c SOURCE_MANIFEST.SHA256
) | tee "$out/UPSTREAM_MANIFEST_CHECK.txt"

sha256sum \
  "$root/vectors/PVC_MAC0_VECTORS_0.1.0.csv" \
  "$root/vectors/PVC_MAC0_DIFFERENTIAL_M1.csv" \
  | tee "$out/VECTOR_HASHES.txt"

echo "PVC-MAC-0 Candidate M1 / v0.2.0 campaign completed successfully"

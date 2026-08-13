#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${1:-$root/build-campaign}"
out="$root/results-0.1.0"

cmake -S "$root" -B "$build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build" -j
ctest --test-dir "$build" --output-on-failure | tee "$out/CTEST.txt"
"$build/pvc-mac0-vector-generator" --output "$out/PVC_MAC0_VECTORS_REGENERATED.csv" --count 48
cmp "$out/PVC_MAC0_VECTORS_REGENERATED.csv" "$root/vectors/PVC_MAC0_VECTORS_0.1.0.csv"
"$build/pvc-mac0-framing-audit" | tee "$out/FRAMING_AUDIT_REGENERATED.txt"
"$build/pvc-mac0-avalanche-probe" | tee "$out/MESSAGE_AVALANCHE_256_REGENERATED.txt"
(
    cd "$root/external/pvc_prf1_c1"
    sha256sum -c SOURCE_MANIFEST.SHA256
) | tee "$out/UPSTREAM_MANIFEST_CHECK.txt"

echo "PVC-MAC-0 v0.1.0 campaign completed successfully"

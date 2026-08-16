#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compiler="${CXX:-g++}"
build_dir="${1:-build-fault-injection}"
output_path="${2:-}"
build_type="${BUILD_TYPE:-Release}"
sanitizer="${SANITIZER:-none}"

cmake -S "$repo_root" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE="$build_type" \
    -DCMAKE_CXX_COMPILER="$compiler" \
    -DPVCROTSYMENC1_BUILD_TESTS=OFF \
    -DPVCROTSYMENC1_BUILD_ANALYSIS=ON \
    -DPVCROTSYMENC1_SANITIZER="$sanitizer" \
    -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
cmake --build "$build_dir" \
    --target pvc-rotsymenc1-fault-injection-campaign \
    --parallel 2

campaign="$build_dir/pvc-rotsymenc1-fault-injection-campaign"
if [[ -n "$output_path" ]]; then
    mkdir -p "$(dirname "$output_path")"
    "$campaign" | tee "$output_path"
else
    "$campaign"
fi

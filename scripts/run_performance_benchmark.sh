#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 BUILD_DIR OUTPUT_JSON [runner options...]" >&2
    exit 2
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$1"
output_json="$2"
shift 2

export CXX="${CXX:-c++}"

cmake -S "${repo_dir}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DPVCROTSYMENC1_BUILD_TESTS=OFF \
    -DPVCROTSYMENC1_BUILD_BENCHMARKS=ON \
    -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
cmake --build "${build_dir}" \
    --target pvc-rotsymenc1-performance-benchmark \
    --parallel 2

python3 "${repo_dir}/scripts/run_performance_benchmark.py" \
    --benchmark "${build_dir}/pvc-rotsymenc1-performance-benchmark" \
    --output "${output_json}" \
    --require-clean \
    "$@"

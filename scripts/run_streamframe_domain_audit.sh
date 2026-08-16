#!/usr/bin/env bash
set -euo pipefail

compiler="${CXX:-g++}"
build_dir="${1:-build-streamframe-domain}"

cmake -S . -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="${compiler}" \
    -DPVCROTSYMENC1_BUILD_TESTS=OFF \
    -DPVCROTSYMENC1_BUILD_ANALYSIS=ON
cmake --build "${build_dir}" --target pvc-rotsymenc1-streamframe-domain-audit --parallel

"${build_dir}/pvc-rotsymenc1-streamframe-domain-audit" \
    --samples 4096 \
    --walsh-variables 12 \
    --walsh-trials 2 \
    --seed 0x53545245414D4631

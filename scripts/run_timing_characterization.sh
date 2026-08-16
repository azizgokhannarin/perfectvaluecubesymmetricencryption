#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -m)" != "x86_64" ]]; then
    printf 'error: the pinned dudect RDTSC backend requires x86_64\n' >&2
    exit 2
fi

compiler="${CXX:-g++}"
build_dir="${1:-build-timing}"
measurements="${PVC_TIMING_MEASUREMENTS:-12000}"
batches="${PVC_TIMING_BATCHES:-3}"
seed="${PVC_TIMING_SEED:-0x54494D494E473031}"
allowed_cpus="$(taskset -pc $$ | sed 's/.*: //')"
cpu="${PVC_TIMING_CPU:-${allowed_cpus%%[-,]*}}"

cmake -S . -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="${compiler}" \
    -DPVCROTSYMENC1_BUILD_TESTS=OFF \
    -DPVCROTSYMENC1_BUILD_ANALYSIS=ON
cmake --build "${build_dir}" --target pvc-rotsymenc1-timing-characterization --parallel

printf 'runner_version=1\n'
printf 'kernel=%s\n' "$(uname -sr)"
printf 'architecture=%s\n' "$(uname -m)"
printf 'cpu_model=%s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p')"
printf 'allowed_cpus=%s\n' "${allowed_cpus}"
printf 'pinned_cpu=%s\n' "${cpu}"
printf 'compiler_command=%s\n' "${compiler}"
"${compiler}" --version | sed -n '1p'

targets=(
    positive-control
    c1-evaluate
    c1-key-only
    c1-streamframe-only
    m1-compute
    m1-verify-mismatch-position
    seal
    open-failure
    open-success
    open-validity-control
)

for target in "${targets[@]}"; do
    printf 'runner_target_begin=%s\n' "${target}"
    taskset -c "${cpu}" \
        "${build_dir}/pvc-rotsymenc1-timing-characterization" \
        --target "${target}" \
        --measurements "${measurements}" \
        --batches "${batches}" \
        --seed "${seed}"
    printf 'runner_target_end=%s\n' "${target}"
done

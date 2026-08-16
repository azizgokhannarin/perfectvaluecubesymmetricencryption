#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

output_dir="$repo_root/build-reproduce-all"
full_performance=0
allow_dirty=0
jobs="${JOBS:-2}"
main_cxx="${CXX:-g++}"
fuzz_cc="${FUZZ_CC:-clang}"
fuzz_cxx="${FUZZ_CXX:-clang++}"
cbmc_bin="${CBMC:-cbmc}"

usage() {
    cat <<'EOF'
usage: ./reproduce_all.sh [options]

Options:
  --output DIR         New output directory (default: build-reproduce-all)
  --full-performance   Run the complete 48-case performance matrix
  --allow-dirty        Permit tracked source changes and record that fact
  -h, --help           Show this help

Environment:
  CXX, FUZZ_CC, FUZZ_CXX, CBMC, JOBS, ASAN_OPTIONS
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            if [[ $# -lt 2 ]]; then
                printf '%s\n' 'missing value for --output' >&2
                exit 2
            fi
            output_dir="$2"
            shift 2
            ;;
        --full-performance)
            full_performance=1
            shift
            ;;
        --allow-dirty)
            allow_dirty=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$output_dir" != /* ]]; then
    output_dir="$repo_root/$output_dir"
fi
if [[ -e "$output_dir" ]]; then
    printf 'output path already exists; select a new directory: %s\n' "$output_dir" >&2
    exit 2
fi

logs_dir="$output_dir/logs"
summary="$output_dir/SUMMARY.txt"
mkdir -p "$logs_dir"

current_stage="initialization"
campaign_finished=0
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git_commit="$(git rev-parse HEAD 2>/dev/null || printf unavailable)"
tracked_status="$(git status --porcelain --untracked-files=no 2>/dev/null || true)"
tracked_dirty=0
if [[ -n "$tracked_status" ]]; then
    tracked_dirty=1
fi

cat > "$summary" <<EOF
format=pvc-rotsymenc1-reproduce-all-v1
construction_version=0.1.0-draft
started_utc=$started_utc
git_commit=$git_commit
tracked_worktree_dirty=$tracked_dirty
allow_dirty=$allow_dirty
full_performance=$full_performance
main_cxx=$main_cxx
fuzz_cxx=$fuzz_cxx
cbmc=$cbmc_bin
jobs=$jobs
asan_options=${ASAN_OPTIONS:-}
EOF

finish_on_exit() {
    local status=$?
    if [[ $campaign_finished -eq 0 ]]; then
        {
            printf 'failed_stage=%s\n' "$current_stage"
            printf 'exit_status=%d\n' "$status"
            printf 'completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf '%s\n' 'status=failed'
        } >> "$summary"
    fi
}
trap finish_on_exit EXIT

run_stage() {
    local label="$1"
    shift
    current_stage="$label"
    printf '\n[%s] %s\n' "$label" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    set +e
    "$@" 2>&1 | tee "$logs_dir/$label.log"
    local command_status=${PIPESTATUS[0]}
    set -e
    if [[ $command_status -ne 0 ]]; then
        printf 'stage.%s=failed:%d\n' "$label" "$command_status" >> "$summary"
        exit "$command_status"
    fi
    printf 'stage.%s=passed\n' "$label" >> "$summary"
}

preflight() {
    local tool
    for tool in cmake ctest git python3 sha256sum "$main_cxx" "$fuzz_cc" "$fuzz_cxx" "$cbmc_bin"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'required tool not found: %s\n' "$tool" >&2
            return 2
        fi
    done
    if ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
        printf 'JOBS must be a positive integer: %s\n' "$jobs" >&2
        return 2
    fi
    if [[ $tracked_dirty -ne 0 && $allow_dirty -eq 0 ]]; then
        printf '%s\n' 'tracked worktree is dirty; commit first or use --allow-dirty' >&2
        return 2
    fi
    local cbmc_version
    cbmc_version="$("$cbmc_bin" --version)"
    if [[ "$cbmc_version" != *"6.10.0"* ]]; then
        printf 'expected CBMC 6.10.0, got: %s\n' "$cbmc_version" >&2
        return 2
    fi
    printf 'cmake=%s\n' "$(cmake --version | sed -n '1p')"
    printf 'python=%s\n' "$(python3 --version)"
    printf 'main_compiler=%s\n' "$("$main_cxx" --version | sed -n '1p')"
    printf 'fuzz_compiler=%s\n' "$("$fuzz_cxx" --version | sed -n '1p')"
    printf 'cbmc=%s\n' "$cbmc_version"
}

verify_manifests() {
    sha256sum --quiet -c DEPENDENCY_MANIFEST.SHA256
    sha256sum --quiet -c PROFILE_MANIFEST.SHA256
    sha256sum --quiet -c SOURCE_MANIFEST.SHA256
    ./scripts/verify_candidate_a1_manifest.sh
    printf '%s\n' 'all retained manifests verified'
}

build_and_test() {
    cmake -S . -B "$output_dir/build-release" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_COMPILER="$main_cxx" \
        -DPVCROTSYMENC1_EQUIVALENCE_CASES=4096 \
        -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
    cmake --build "$output_dir/build-release" --parallel "$jobs"
    ctest --test-dir "$output_dir/build-release" --output-on-failure
}

verify_kat_and_differential() {
    python3 scripts/verify_vectors.py \
        --cli "$output_dir/build-release/pvc-rotsymenc1"
    "$output_dir/build-release/pvc-rotsymenc1-equivalence" --count 4096
    python3 scripts/verify_cross_platform_conformance.py \
        --generator "$output_dir/build-release/pvc-rotsymenc1-cross-platform-conformance"
}

run_fuzz_seeds() {
    CC="$fuzz_cc" CXX="$fuzz_cxx" cmake -S . -B "$output_dir/build-fuzz" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DPVCROTSYMENC1_BUILD_FUZZERS=ON \
        -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
    cmake --build "$output_dir/build-fuzz" \
        --target pvc-rotsymenc1-fuzz-seal-equivalence \
                 pvc-rotsymenc1-fuzz-open-equivalence \
        --parallel "$jobs"
    ctest --test-dir "$output_dir/build-fuzz" -L fuzz --output-on-failure
}

run_cbmc() {
    CBMC="$cbmc_bin" CBMC_RESULTS_DIR="$output_dir/cbmc" \
        ./scripts/run_cbmc.sh
}

run_streamframe() {
    CXX="$main_cxx" ./scripts/run_streamframe_domain_audit.sh \
        "$output_dir/build-streamframe"
}

run_performance() {
    cmake -S . -B "$output_dir/build-performance" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_COMPILER="$main_cxx" \
        -DPVCROTSYMENC1_BUILD_TESTS=OFF \
        -DPVCROTSYMENC1_BUILD_BENCHMARKS=ON \
        -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
    cmake --build "$output_dir/build-performance" \
        --target pvc-rotsymenc1-performance-benchmark \
        --parallel "$jobs"

    local runner=(
        python3 scripts/run_performance_benchmark.py
        --benchmark "$output_dir/build-performance/pvc-rotsymenc1-performance-benchmark"
        --output "$output_dir/performance.json"
    )
    if [[ $allow_dirty -eq 0 ]]; then
        runner+=(--require-clean)
    fi
    if [[ $full_performance -eq 0 ]]; then
        runner+=(
            --sizes 0,64,4096
            --tags 128,192,256
            --operations seal,open-success
            --samples 3
            --large-samples 3
            --target-ms 10
        )
    fi
    "${runner[@]}"
    python3 scripts/summarize_performance_benchmark.py \
        --verify-only "$output_dir/performance.json"
}

write_artifact_manifest() {
    (
        cd "$output_dir"
        {
            find logs cbmc -type f -print
            printf '%s\n' performance.json
        } | LC_ALL=C sort | while IFS= read -r file; do
            sha256sum "$file"
        done
    ) > "$output_dir/ARTIFACTS.SHA256"
}

run_stage preflight preflight
run_stage manifests-before verify_manifests
run_stage release-tests build_and_test
run_stage kat-differential verify_kat_and_differential
run_stage fuzz-seeds run_fuzz_seeds
run_stage cbmc run_cbmc
run_stage streamframe run_streamframe
run_stage performance run_performance
run_stage manifests-after verify_manifests

current_stage="artifact-manifest"
write_artifact_manifest
printf 'stage.artifact-manifest=passed\n' >> "$summary"
printf 'completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$summary"
printf '%s\n' 'status=passed' >> "$summary"
campaign_finished=1

printf '\nPVC-RotSymEnc-1 reproduction campaign passed.\n'
printf 'Summary: %s\n' "$summary"
printf 'Artifact hashes: %s\n' "$output_dir/ARTIFACTS.SHA256"

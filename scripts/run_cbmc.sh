#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cbmc_bin="${CBMC:-cbmc}"
expected_version="6.10.0"
expected_aead_sha256="92ddd474cae8c173bd16df5aca3b88c34c8af431cecf7727a90fb6298a71160d"
results_dir="${CBMC_RESULTS_DIR:-build-cbmc}"
generated_source="$results_dir/pvc_aead0_aead_cbmc.cpp"

if ! command -v "$cbmc_bin" >/dev/null 2>&1; then
    printf 'CBMC executable not found: %s\n' "$cbmc_bin" >&2
    exit 2
fi

version_output="$("$cbmc_bin" --version)"
if [[ "$version_output" != *"$expected_version"* ]]; then
    printf 'Expected CBMC %s, got: %s\n' "$expected_version" "$version_output" >&2
    exit 2
fi

actual_aead_sha256="$(sha256sum external/pvc_aead0_a1/src/aead.cpp | awk '{print $1}')"
if [[ "$actual_aead_sha256" != "$expected_aead_sha256" ]]; then
    printf 'Candidate A1 source hash changed; review the CBMC adapter before rerunning.\n' >&2
    printf 'expected=%s\nactual=%s\n' "$expected_aead_sha256" "$actual_aead_sha256" >&2
    exit 2
fi

mkdir -p "$results_dir"
sed -f verification/cbmc/prepare_aead.sed \
    external/pvc_aead0_a1/src/aead.cpp > "$generated_source"

printf 'CBMC=%s\nA1_SHA256=%s\n' "$version_output" "$actual_aead_sha256" \
    > "$results_dir/PROVENANCE.txt"

run_proof() {
    local label="$1"
    shift
    local log="$results_dir/$label.txt"
    printf '[CBMC] %s\n' "$label"
    if "$@" > "$log" 2>&1; then
        grep -E '^\*\* [0-9]+ of|VERIFICATION (SUCCESSFUL|FAILED)' "$log" || true
    else
        tail -n 200 "$log" >&2
        return 1
    fi
}

cpp_common=(
    "$cbmc_bin"
    --cpp11
    -Dconstexpr=
    -I verification/cbmc/include
    "$generated_source"
    verification/cbmc/aead_harness.cpp
    --unwind 82
    --unwinding-assertions
    --object-bits 12
    --drop-unused-functions
    --verbosity 4
)

run_proof frames \
    "${cpp_common[@]}" \
    --function verify_frames

run_proof seal-lengths \
    "${cpp_common[@]}" \
    --function verify_seal_lengths \
    --slice-formula \
    --property verify_seal_lengths.assertion.1 \
    --property verify_seal_lengths.assertion.2 \
    --property verify_seal_lengths.assertion.3

run_proof open-control-flow \
    "${cpp_common[@]}" \
    --function verify_open_control_flow \
    --slice-formula \
    --property research_keyed_return_output_a2.assertion.1 \
    --property research_keyed_return_output_a2.assertion.2 \
    --property research_keyed_return_output_a2.assertion.3 \
    --property verify_tag.assertion.1 \
    --property verify_tag.assertion.2 \
    --property verify_open_control_flow.assertion.1 \
    --property verify_open_control_flow.assertion.2 \
    --property verify_open_control_flow.assertion.3 \
    --property verify_open_control_flow.assertion.4 \
    --property verify_open_control_flow.assertion.5 \
    --property verify_open_control_flow.assertion.6 \
    --property verify_open_control_flow.assertion.7 \
    --property verify_open_control_flow.assertion.8 \
    --property verify_open_control_flow.assertion.9 \
    --property verify_open_control_flow.assertion.10

run_proof counter-domain \
    "$cbmc_bin" \
    --c11 \
    verification/cbmc/counter_harness.c \
    --unwinding-assertions \
    --unsigned-overflow-check \
    --verbosity 4

printf 'CBMC bounded verification completed. Logs: %s\n' "$results_dir"

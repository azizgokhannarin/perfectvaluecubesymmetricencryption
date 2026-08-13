#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/external/pvc_aead0_a1"
sha256sum -c CANDIDATE_MANIFEST.SHA256
sha256sum -c DEPENDENCY_MANIFEST.SHA256

# Retained Nonce Management And Misuse Results

## Question

Can the documented nonce-reuse consequence be reproduced through the canonical
wrapper, and how does an analysis-only persistent allocator behave under normal
restart, process termination, concurrent allocation, and state rollback?

## Method

Campaign version 1 was defined in commit `5a674eb` before measurement. It uses
the canonical wrapper for the XOR demonstration, an exact in-memory detector,
a deterministic collision simulator, and a locked file-backed 192-bit counter.
The full method and pre-registered alarms are in
`docs/NONCE_MISUSE_CAMPAIGN.md`.

## Parameters

```text
date = 2026-08-16
host kernel = Linux 6.12.95+deb13-amd64 x86_64
temporary filesystem = tmpfs
GCC = 14.2.0
Clang = 19.1.7
seed = 0x4E4F4E43454D4754
Release profiles = GCC, Clang
sanitizer profiles = Clang ASan, Clang UBSan
GitHub Actions = run 31971780631, 23/23 jobs
```

## Files

- `GCC14_PRIMARY.txt`: GCC Release primary record.
- `CLANG19_PRIMARY.txt`: Clang Release primary record.
- `CLANG19_ASAN.txt`: Clang ASan record with local leak detection disabled.
- `CLANG19_UBSAN.txt`: Clang UBSan record.
- `CLANG19_ASAN_LSAN_ATTEMPT.txt`: retained failed local LSan attempt showing
  the managed runner's `ptrace` restriction.

The four completed campaign records are byte-identical and have SHA-256
`84dfa927279de9095dae4547b2df3510fa7c094d5895d36f489e1fe36bcbc0b7`.

## Result

The campaign reproduced both pre-registered known misuse findings: the XOR
relation held over all 96 tested bytes, and snapshot rollback repeated eight of
eight post-snapshot nonces. The detector caught same-key reuse and all rollback
repeats when its own state was not rolled back.

Normal restart produced 257 unique allocations. Four process-crash points
caused no reuse of a nonce already returned to a caller. Eight processes made
1,024 unique, gap-free allocations. The 192-bit simulation observed zero
collisions in 65,536 samples; the 24-bit control observed 129. The
pre-registered unexpected-failure count was zero, and completed ASan/UBSan runs
reported no finding. GitHub Actions run `31971780631` passed all four nonce
profiles and all 23 workflow jobs.

## Interpretation

The tested persistence protocol handled the bounded local process-crash and
multi-process model. Snapshot rollback remains outside what a standalone local
counter can prevent. The result confirms a usage hazard and characterizes a
prototype; it does not change Candidate A1 or establish misuse resistance.

## Limitations

The crash experiment used immediate process exit, not power interruption. The
state lived on local `tmpfs`; network filesystems, disk/controller persistence,
VM clones, hostile storage, and cross-host allocation were not tested. Local
LeakSanitizer could not run under `ptrace`, though ASan itself completed with
leak checking disabled and CI is configured to retain leak checking. The
deterministic simulator is not a random nonce generator, and zero observed
192-bit collisions is not proof of collision freedom.

## Reproduction

```bash
CXX=g++ ./scripts/run_nonce_misuse_campaign.sh \
  build-nonce-misuse-gcc /tmp/GCC14_PRIMARY.txt
CXX=clang++ ./scripts/run_nonce_misuse_campaign.sh \
  build-nonce-misuse-clang /tmp/CLANG19_PRIMARY.txt
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
  BUILD_TYPE=RelWithDebInfo SANITIZER=address CXX=clang++ \
  ./scripts/run_nonce_misuse_campaign.sh \
  build-nonce-misuse-asan /tmp/CLANG19_ASAN.txt
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  BUILD_TYPE=RelWithDebInfo SANITIZER=undefined CXX=clang++ \
  ./scripts/run_nonce_misuse_campaign.sh \
  build-nonce-misuse-ubsan /tmp/CLANG19_UBSAN.txt
```

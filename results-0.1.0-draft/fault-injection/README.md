# Fault-Injection Campaign Records

## Question

How do registered single-software-fault models affect canonical authentication,
post-authentication plaintext computation, and C1 finalization outputs?

## Method

The primary campaign, targeted localization, and targeted replication are
defined in `docs/FAULT_INJECTION_CAMPAIGN.md`,
`docs/FAULT_INJECTION_LOCALIZATION.md`, and
`docs/FAULT_INJECTION_REPLICATION.md`. The definition commits are `4abd98c`,
`770ade7`, and `db40564`. All records are deterministic text output from the
standalone analysis executable; the candidate construction was not modified.

## Parameters

```text
seed = 0x4641554C54494E4A
state bits = 4,224
primary state faults = 16,896
replication cases = 8 per tag profile
replication state faults = 101,376
compilers = GCC 14.2 and Clang 19.1
sanitizers = Clang ASan and UBSan
```

## Records

Primary GCC, Clang, ASan, and UBSan records are byte-identical:

```text
51cb843ad1dd765bd968e6f6c48d38d9b7bdda4dad6fad9f826c57921855d67f
```

Localization GCC and Clang records are byte-identical:

```text
fb655ee5b82bd02addd25215dfd2d3581941e9c6b598c57cd6b214ca7e42c6ae
```

Replication GCC, Clang, ASan, and UBSan records are byte-identical:

```text
809830e9ce701a06bf1b189652dd52f29d982712dc9eb3abdc8a86c387f880f6
```

`CLANG19_ASAN_LSAN_ATTEMPT.txt` retains the local LeakSanitizer environment
failure, SHA-256
`94c3532a59cb16ca6ac81d82ea87ddac0ddd681e22afb310285fae2aa4dd4a4e`.
The managed local runner is ptrace-restricted. Hosted CI run `31973527136`
completed all 27 jobs, including the four-profile fault matrix.

## Result

No actual altered canonical tuple was accepted. Explicit models that removed
comparison or authentication-return operations produced their registered
bypasses. C1 state-fault replication found silent MAC prefixes in every case
and 35 distance-one candidates across 12 of 24 cases. All distance-one
candidates were cube-state faults affecting the final tag byte.

## Interpretation

The recurring result is a bounded structural warning at the tested late
software injection boundary. It is not evidence that a physical attacker can
realize the fault or a demonstration of practical forgery or key recovery.

## Limitations

The campaign uses deterministic inputs, one-bit faults, and one C1 injection
boundary. It excludes physical timing and controllability, earlier phases,
combined or persistent faults, attacker knowledge, and fault probability. No
bounded negative result establishes fault resistance or cryptographic security.

## Reproduction

```bash
CXX=g++ ./scripts/run_fault_injection_campaign.sh build-fault-gcc
build-fault-gcc/pvc-rotsymenc1-fault-injection-campaign --localize
build-fault-gcc/pvc-rotsymenc1-fault-injection-campaign --replicate
```

# Fault-Injection Targeted Replication

## Status

This document pre-registers a targeted replication prompted by the localized
128-bit distance-one C1 state-fault candidate. Results are pending. The
construction, canonical vectors, injection point, and state-bit enumeration are
unchanged.

## Question

Do unchanged MAC tag prefixes and distance-one prefix changes recur across
additional deterministic inputs at the same finalization-boundary injection
point, and which tag profiles exhibit them in this bounded campaign?

## Method

For each 128-, 192-, and 256-bit tag profile, the `--replicate` mode generates
eight deterministic cases from a profile-separated seed stream. Each case has
independent role keys, a 192-bit nonce, 33 bytes of AD, and 96 bytes of
plaintext. The canonical wrapper first seals and successfully opens the case.

The exact M1 frame is then evaluated to the frozen C1 state after transcript
return. Each of the 4,224 modeled state bits is flipped individually before the
unmodified finalizer. The campaign records tag-prefix Hamming distances,
per-profile counts of cases containing unchanged or distance-one results, and
the exact coordinates of all distance-one candidates.

## Parameters

```text
base campaign definition commit = 4abd98c
localization definition commit = 770ade7
base seed = 0x4641554C54494E4A
cases per tag profile = 8
tag profiles = 128, 192, 256 bits
state faults per case = 4,224
faults per profile = 33,792
total state faults = 101,376
injection point = after transcript return, before finalization
compilers = GCC 14.2 and Clang 19.1
```

## Pre-Registered Interpretation Rules

- A distance-zero prefix is a silent observation at this input, profile, and
  injection point. It is not a forgery.
- A distance-one result means that a supplied tag differing at the recorded bit
  equals the faulted recomputation for that exact modeled state fault. It is a
  fault-assisted tag candidate, not evidence that the fault is physically
  achievable or predictable.
- Recurrence across cases is evidence that the primary observation was not
  unique to one deterministic input. It does not establish a universal rate or
  a practical attack.
- Any baseline mismatch, compiler disagreement, sanitizer finding, or altered
  canonical acceptance is an alarm.

## Result

Pending the first replication run after this definition is committed.

## Limitations

The campaign uses eight cases per profile and one late injection point. It does
not sample physical fault timing or controllability, earlier C1 phases,
multi-fault combinations, attacker knowledge, or key recovery. Counts across
deterministic cases are descriptive and are not an estimate of real-world fault
probability.

## Reproduction

```bash
build-fault-gcc/pvc-rotsymenc1-fault-injection-campaign --replicate
build-fault-clang/pvc-rotsymenc1-fault-injection-campaign --replicate
```

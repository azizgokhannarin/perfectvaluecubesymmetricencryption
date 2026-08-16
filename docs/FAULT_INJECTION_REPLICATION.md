# Fault-Injection Targeted Replication

## Status

This targeted replication is complete. Its definition was committed as
`db40564` before measurement after the localized 128-bit distance-one C1
state-fault candidate. The construction, canonical vectors, injection point,
and state-bit enumeration are unchanged.

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

GCC 14.2, Clang 19.1, Clang ASan, and Clang UBSan produced byte-identical
records with SHA-256
`809830e9ce701a06bf1b189652dd52f29d982712dc9eb3abdc8a86c387f880f6`.
No baseline, compiler, or sanitizer alarm occurred.

```text
profile  cases  faults  unchanged  distance-one  cases unchanged  cases distance-one
128      8      33792   3671       9             8                3
192      8      33792   2462       18            8                6
256      8      33792   1666       8             8                3
```

Every distance-one candidate originated in the cube region. All changed tag
bits were in the final tag byte: bits 120, 122, 124--127 for the 128-bit
profile; 184--191 for the 192-bit profile; and 248, 250, 252, 254, and 255 for
the 256-bit profile. Every case in every profile contained at least one silent
prefix fault. Distance-one candidates occurred in 3/8, 6/8, and 3/8 cases for
the respective profiles.

## Interpretation

The recurrence shows that the primary silent and distance-one observations
were not unique to one deterministic input. Their restriction to the last tag
byte is consistent with a late cube-state fault remaining latent until the
last part of sequential finalization output. This is an implementation-based
interpretation, not a formal proof of the mechanism.

The pre-registered follow-up in `FAULT_FINALIZATION_DIAGNOSIS.md` subsequently
showed that C1 always produces 32 bytes and that prefix truncation explains a
substantial part of the 128- and 192-bit concentration. All distance-one cases
grew to high distance when squeeze observation continued to 64 bytes.

The campaign therefore records a bounded structural warning and exact
fault-assisted tag candidates for this software model. It does not establish
that an attacker can predict or induce the required state fault, supply the
corresponding altered tag, recover a key, or obtain a practical forgery.

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

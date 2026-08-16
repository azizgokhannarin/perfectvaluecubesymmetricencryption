# Fault-Injection Targeted Localization

## Status

This document registers a targeted follow-up after campaign version 1 produced
unchanged finalization outputs and one 128-bit MAC-prefix result at Hamming
distance one. Localization results are pending. The default campaign behavior,
fault set, construction, and canonical vectors remain unchanged.

## Question

Which modeled C1 state regions account for the unchanged outputs, and what
exact finalization-boundary state bit and tag bit form the observed 128-bit
distance-one candidate?

## Method

The campaign executable receives the optional `--localize` flag. It reruns the
same deterministic 4,224 state-bit enumeration for the stream case and each MAC
tag profile. For distance-zero results it counts the originating state region:
cube, axis control, amount control, feedback, or transcript. For every
distance-one result it records the exact state-bit index, state region, and
changed tag/output-bit index.

No fault is added, removed, or selected based on a desired outcome. Default
execution without `--localize` remains byte-identical to the pre-registered
campaign output.

## Parameters

```text
campaign definition commit = 4abd98c
seed = 0x4641554C54494E4A
injection point = after transcript return, before finalization
state bits = 4,224
profiles = stream 256; MAC 128, 192, 256
compilers = GCC 14.2 and Clang 19.1
```

## Result

Pending the first localization run after this follow-up definition is
committed.

## Interpretation

Pending measurement. An unchanged prefix means that the selected injected bit
did not change the observed prefix at this injection point and input. It does
not mean the complete internal trajectory was unchanged. A distance-one tag
candidate identifies a precise software model relation, not fault feasibility,
attacker knowledge, or a practical forgery.

## Limitations

The limitations of `FAULT_INJECTION_CAMPAIGN.md` apply. This follow-up uses the
same single input per profile and one injection boundary. It does not estimate
how often a state bit is physically targetable or whether an attacker can
predict, induce, or observe the corresponding faulted tag.

## Reproduction

```bash
build-fault-gcc/pvc-rotsymenc1-fault-injection-campaign --localize
build-fault-clang/pvc-rotsymenc1-fault-injection-campaign --localize
```

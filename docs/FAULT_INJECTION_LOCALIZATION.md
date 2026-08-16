# Fault-Injection Targeted Localization

## Status

This targeted follow-up is complete. Its definition was committed as
`770ade7` before measurement after campaign version 1 produced unchanged
finalization outputs and one 128-bit MAC-prefix result at Hamming distance one.
The default campaign behavior, fault set, construction, and canonical vectors
remain unchanged.

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

GCC 14.2 and Clang 19.1 produced byte-identical records with SHA-256
`fb655ee5b82bd02addd25215dfd2d3581941e9c6b598c57cd6b214ca7e42c6ae`.
Every unchanged result originated in the 4,096-bit cube region: 232 stream
faults and 420, 333, and 272 MAC faults for the 128-, 192-, and 256-bit
profiles. No axis-control, amount-control, feedback, or transcript bit fault
left the observed prefix unchanged.

The sole primary distance-one candidate was the 128-bit MAC case at state bit
2,763. It maps to cube cell 345, coordinate `(1, 3, 5)`, cell bit 3. The
changed tag bit was 122, or byte 15 bit 2 with zero-based indexing.

## Interpretation

The localization confines the primary silent observations and distance-one
candidate to cube-state faults in this model. An unchanged prefix means only
that the selected injected bit did not change the observed prefix at this
injection point and input; it does not mean the complete internal trajectory
was unchanged. The exact distance-one relation is a software-model candidate,
not fault feasibility, attacker knowledge, or a practical forgery.

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

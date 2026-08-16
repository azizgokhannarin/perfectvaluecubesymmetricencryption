# Fault-Finalization Diagnostic Records

## Question

Are the registered silent and distance-one tag-prefix faults caused by a
harness artifact, a fixed inactive region, or delayed state-dependent squeeze
reachability combined with profile truncation?

## Method

The pre-registered definition is `docs/FAULT_FINALIZATION_DIAGNOSIS.md`, commit
`698cace`. The campaign checked fault persistence, matched an analysis mirror
against canonical 32-byte output, traced retained faults through 64 bytes,
emitted exact coordinate maps, and evaluated two dependency controls. The
candidate construction was not modified.

## Parameters

```text
primary entry faults = 101,376
retained stepwise traces = 7,834
dependency-family cube faults = 196,608
canonical output = 32 bytes
analysis-only continuation = 32 bytes
profiles = GCC 14.2, Clang 19.1, Clang ASan, Clang UBSan
```

## Records

All four diagnostic summaries are byte-identical:

```text
180ec4c4b2b7d5ff7bd26a6a45984c8f6bccc04e8374d8e8db053390b86c4fc8
```

The GCC and Clang exact maps are byte-identical:

```text
75210707565177495693f266038e79d7ebd930f99db17be8e769c363c74dce76
```

The map has one header and 7,834 data rows. It records profile, case, state
bit, cube coordinate, prefix/full/extended distances, first changed byte, and
first controller/state divergence stages.

Local LeakSanitizer remains unavailable in the ptrace-restricted managed
runner. GitHub Actions run `31978436170` completed 27/27 jobs, including all
four fault-analysis profiles and hosted LeakSanitizer coverage.

## Result

All entry and mirror checks passed. No retained fault reached the controller
before squeeze. Of 7,799 prefix-silent faults, 6,676 first became visible after
the selected prefix and 1,123 remained silent through 64 observed bytes. All
35 prefix-distance-one faults grew to distance 115--195 at 64 bytes. Neither
dependency family had an all-case coordinate intersection.

## Interpretation

The data support delayed, input-dependent squeeze reachability plus profile
truncation rather than a harness-copy error or one fixed inactive coordinate.
This is a bounded software-fault characteristic, not a normal-input attack or
evidence of physical feasibility, forgery, state recovery, or key recovery.

## Limitations

The 64-byte continuation is outside Candidate C1. The valid-nonce family also
changes ciphertext; the fixed-frame key family is below the complete wrapper.
Only one injection boundary and deterministic cases were tested. Local
derivatives and coordinate overlaps do not establish global algebraic degree
or real-world fault probability.

## Reproduction

```bash
CXX=g++ ./scripts/run_fault_injection_campaign.sh build-fault-diagnosis
build-fault-diagnosis/pvc-rotsymenc1-fault-injection-campaign --diagnose
build-fault-diagnosis/pvc-rotsymenc1-fault-injection-campaign --map
```

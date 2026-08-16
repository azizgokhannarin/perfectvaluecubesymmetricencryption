# Fault-Finalization Diagnostic Campaign

## Status

This document pre-registers diagnostic campaign version 1. Results are
pending. The construction, public API, vendored C1/M1/A1 implementation, and
canonical vectors are unchanged. All new behavior is confined to optional
analysis modes in the existing software fault-injection executable.

## Question

Do silent and Hamming-distance-one MAC-prefix observations at the registered
post-return, pre-finalization fault boundary arise because a one-bit cube
difference remains local until the tag-profile truncation boundary, or are
they explained by a harness error, finalizer-mirror discrepancy, fixed
projection, inactive coordinates, or broader weak diffusion?

## Source Observation

Candidate C1 always generates 32 output bytes. M1 returns the first 16, 24, or
32 bytes according to the selected tag profile. Therefore the last observed
tag byte for the 128- and 192-bit profiles is a truncation boundary, not the
last C1 squeeze byte. This campaign treats truncation and sequential squeeze
as separate effects.

## Method

The optional `--diagnose` mode regenerates the exact eight deterministic cases
for each tag profile from the targeted replication campaign. It enumerates the
same 4,224 single-bit entry faults and retains the previously observed
prefix-silent and prefix-distance-one cases for tracing.

An analysis-only finalizer mirror uses the frozen public C1 state-transition
operations and independently spells out the finalization binding and output
selection equations. For every retained fault, its first 32 bytes must match
the unmodified `research_bound_output_a2` result byte for byte. The mirror then
continues the existing squeeze state through bytes 32--63 without re-entering
the domain. These extra bytes are an analysis-only continuation, not a
candidate tag or proposed API.

The trace records:

- the full modeled state distance immediately after injection;
- state distance after finalization entry, each of 16 binding symbols,
  squeeze entry, and each emitted byte;
- the first controller divergence and first state distance other than one;
- first changed output byte;
- distances over the profile prefix, canonical 32 bytes, and analysis-only
  64-byte continuation;
- exact cube coordinates and cell-bit positions for retained faults.

The optional `--map` mode emits the exact retained set as deterministic CSV.

Two dependency controls each enumerate all 4,096 cube bits over eight cases
per profile:

1. a fixed key pair with changing nonces and otherwise fixed AD/plaintext,
   using valid canonical seal/open tuples; ciphertext necessarily changes, so
   this is an operational nonce family rather than a nonce-only C1 control;
2. a fixed framed M1 message with changing authentication keys, which isolates
   C1 key dependence but is not a collection of complete seal tuples.

Set intersections, unions, and pairwise Jaccard ranges are descriptive. They
are not physical fault probabilities or independence estimates.

## Parameters

```text
diagnosis version = 1
base campaign definition = 4abd98c
localization definition = 770ade7
replication definition = db40564
base seed = 0x4641554C54494E4A
family seed = 0x4641554C5446414D
tag profiles = 128, 192, 256 bits
primary cases per profile = 8
primary state faults = 101,376
dependency families = 2
family cases per profile = 8
family cube faults = 196,608
canonical output bytes = 32
analysis-only continuation bytes = 32
compilers = GCC 14.2 and Clang 19.1 on GNU/Linux
sanitizers = Clang AddressSanitizer and UndefinedBehaviorSanitizer
```

## Pre-Registered Interpretation Rules

- Any injection-entry distance other than exactly one is a harness alarm.
- Any mismatch between the analysis mirror and the canonical first 32 bytes is
  a mirror/harness alarm; continuation results must then not be interpreted.
- The prior 3,671/2,462/1,666 silent and 9/18/8 distance-one profile counts
  must reproduce before tracing is interpreted.
- If a difference stays at one state bit until its first changed output byte
  and grows after the profile boundary, that supports a late-influence or
  permutation-only path at this input. It does not establish global algebraic
  degree or a physical attack.
- If profile-silent faults change later canonical bytes, prefix truncation is
  part of the observation. If they remain silent through 32 or 64 bytes,
  inactive/projection hypotheses receive more attention but are not proven.
- Stable fault-coordinate sets under fixed-key nonce changes suggest less
  transcript dependence; stable sets under fixed-frame key changes suggest
  less key dependence. Low overlap suggests dependence but does not identify
  a secret or enable state recovery.
- A local distance-one derivative does not establish a globally affine output
  bit, C1 distinguishability, state recovery, key recovery, or forgery.
- No construction repair will be proposed from this campaign until harness,
  implementation, specification, and construction explanations are separated.

## Result

Pending the first campaign run after this definition is committed.

## Limitations

- The experiment retains the existing deterministic software fault model and
  exact injection boundary. It does not demonstrate physical targeting.
- The traced set is selected by prefix distance zero or one. Higher-distance
  faults are enumerated for reproduction but are not traced step by step.
- The 64-byte continuation is outside frozen Candidate C1 semantics.
- Valid nonce-family cases also change ciphertext, while the fixed-frame key
  family is below the complete wrapper. Neither family is a pure causal proof.
- Coordinate overlap and local derivatives do not measure real-world fault
  rates or cryptographic security.

## Reproduction

```bash
CXX=g++ ./scripts/run_fault_injection_campaign.sh build-fault-diagnosis
build-fault-diagnosis/pvc-rotsymenc1-fault-injection-campaign --diagnose
build-fault-diagnosis/pvc-rotsymenc1-fault-injection-campaign --map
```

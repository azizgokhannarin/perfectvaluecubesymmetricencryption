# Fault-Finalization Diagnostic Campaign

## Status

Diagnostic campaign version 1 is complete. Its definition was committed as
`698cace` before measurement. The construction, public API, vendored C1/M1/A1
implementation, and canonical vectors are unchanged. All new behavior is
confined to optional analysis modes in the existing software fault-injection
executable.

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

GCC 14.2, Clang 19.1, Clang ASan, and Clang UBSan produced byte-identical
diagnostic records with SHA-256
`180ec4c4b2b7d5ff7bd26a6a45984c8f6bccc04e8374d8e8db053390b86c4fc8`.
GCC and Clang also produced byte-identical 7,835-line maps (one header and
7,834 retained faults) with SHA-256
`75210707565177495693f266038e79d7ebd930f99db17be8e769c363c74dce76`.
No compiler, sanitizer, or campaign alarm occurred. GitHub Actions run
`31978436170` completed all 27 jobs, including the four fault-analysis
profiles and hosted LeakSanitizer coverage.

All 101,376 injected entry states differed from their baseline by exactly the
registered single bit. The analysis mirror matched all 24 baseline canonical
outputs and all 7,834 retained faulted outputs over the canonical 32 bytes.
The prior silent and distance-one counts reproduced exactly.

No retained fault showed a controller difference at the recorded boundaries
after finalization entry, any of the 16 controller-binding symbols, or squeeze
entry. Every distance-one fault and 6,700 of 7,799 prefix-silent faults first
showed a controller difference at a recorded squeeze boundary. The controller
remained equal through the 64-byte observation for 1,099 prefix-silent faults.

```text
profile  prefix-silent  first change after prefix  full-32 silent  64-byte silent
128      3671           3411                       1683            260
192      2462           2026                       1709            436
256      1666           1239                       1666            427
```

Across the 7,799 prefix-silent faults, 6,676 first changed output only after
the selected profile prefix. A total of 5,058 remained silent over canonical
32-byte output, while 1,123 remained silent through the analysis-only 64-byte
continuation.

```text
profile  prefix-HD1  full-32 distance  64-byte distance  single-bit until first output
128      9           56--69            180--195          7
192      18          25--36            144--173          9
256      8           1                 115--146          3
```

All 35 distance-one observations occurred at the profile's final prefix byte.
None remained distance one in the 64-byte continuation. Every retained fault
originated in cube state; no distance-one state bit repeated across the eight
primary cases within a profile.

The fixed-key valid-nonce and fixed-frame varying-key controls both had empty
all-case intersections for silent and distance-one sets in every profile.
Every distance-one set also had zero pairwise overlap within each family and
profile. Silent-set pairwise Jaccard values ranged from 0 to 0.134 across the
registered families. The valid-nonce family also changes ciphertext, as noted
in the method.

## Interpretation

The entry and mirror checks provide evidence against the registered harness
timing/copy and finalizer-mirror hypotheses. No controller difference survives
to a recorded binding boundary in these cases. The measurements are consistent
with the selected difference following a dynamic cube trajectory until squeeze
output or a squeeze move reaches it. Once a changed output byte is absorbed,
later output generally diverges strongly.

The 128- and 192-bit final-byte concentration is therefore substantially
explained by M1 prefix truncation: the same fault usually affects later
canonical C1 bytes. The 256-bit distance-one cases occur at the actual final
canonical byte, but the difference grows to 115--146 bits in the analysis-only
continuation. Zero coordinate intersection under both dependency controls is
evidence against one fixed globally inactive cube region at these bounds and
is consistent with key- and transcript-dependent access trajectories.

This is a confirmed structural characteristic of the exact software fault
model at one late boundary. It does not establish a normal-input distinguisher,
global algebraic degree, physical fault feasibility, forgery, state recovery,
or key recovery. The 1,123 continuation-silent observations remain a bounded
coverage warning and require no reinterpretation as a practical attack.

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

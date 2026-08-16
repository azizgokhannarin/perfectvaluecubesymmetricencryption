# Attack Log

## 2026-08-17: Dynamic squeeze reachability after a late state fault

### Classification

Confirmed bounded structural characteristic under the registered software
fault model. The result localizes earlier silent and distance-one tag-prefix
observations to profile truncation and input-dependent squeeze reachability. It
is not a normal-input distinguisher, physical-fault demonstration, forgery,
state-recovery result, or key-recovery result.

### Question

Do the earlier final-byte observations come from a harness artifact, a fixed
inactive cube region, or a one-bit difference that remains local until the
sequential squeeze reaches it?

### Method and parameters

The definition was committed as `698cace` before measurement. An analysis
mirror traced state differences across finalization entry, 16 binding symbols,
squeeze entry, 32 canonical output bytes, and a 32-byte analysis-only
continuation. It checked all 101,376 registered entry faults, traced 7,834
prefix-silent or distance-one faults, retained an exact coordinate map, and
ran 196,608 cube faults in fixed-key valid-nonce and fixed-frame varying-key
controls. Four compiler/sanitizer profiles were compared.

### Result

Every entry fault was exactly one bit, and the mirror matched every checked
canonical and faulted 32-byte output. No retained fault showed a controller
difference at a recorded finalization-entry or binding boundary. Of 7,799
prefix-silent faults, 6,676 first affected output after the selected prefix,
5,058 remained silent for the canonical 32 bytes, and 1,123 remained silent
for 64 observed bytes. All 35
prefix-distance-one cases grew to 115--195 output bits at 64 bytes. Coordinate
intersections were empty across every registered key/nonce family and profile.

### Interpretation and limitations

The observed bit follows a key- and transcript-dependent cube trajectory until
squeeze output or squeeze feedback reaches it; absorbing a changed output then
causes broader divergence. Prefix truncation explains much of the 128- and
192-bit concentration. The exact finalizer still has bounded late-reachability
and continuation-silent cases, but no fixed globally inactive coordinate was
identified. The continuation is not Candidate C1 output, the families are
small and partly confounded as documented, and no attacker capability or
cryptographic advantage was demonstrated.

### Reproduction

```bash
build-fault-diagnosis/pvc-rotsymenc1-fault-injection-campaign --diagnose
build-fault-diagnosis/pvc-rotsymenc1-fault-injection-campaign --map
```

See `FAULT_FINALIZATION_DIAGNOSIS.md` and the retained raw records for the
complete parameters and interpretation rules.

## 2026-08-16: Finalization-boundary software fault injection

### Classification

Confirmed bounded software-fault-model warning. The campaign found recurrent
silent C1 output-prefix faults and exact distance-one fault-assisted tag
candidates at one late injection boundary. This is not a demonstrated physical
fault, practical forgery, key-recovery attack, or full fault-resistance result.

### Question

Can a modeled single data, control-flow, or finalization-adjacent C1 state fault
bypass canonical authentication or create low-distance stream/tag outputs?

### Method and parameters

Campaign version 1 used seed `0x4641554C54494E4A`. It exercised actual
canonical input mutations, explicit models that omit a comparison or failed-
authentication return, post-authentication counter/nonce corruption, and all
4,224 modeled C1 state bits after transcript return and before finalization.
The targeted replication enumerated 101,376 state faults across eight
deterministic cases for each 128-, 192-, and 256-bit tag profile. GCC 14.2,
Clang 19.1, ASan, and UBSan outputs were compared.

### Result

Canonical `open` accepted none of the altered real tuples. The explicit
removed-operation models produced their pre-registered bypasses, and every
post-authentication counter/nonce fault corrupted released plaintext. In the
primary C1 cases, 232 stream faults and 420/333/272 MAC faults left the
observed prefix unchanged. Localization placed all such faults in cube state
and identified one 128-bit distance-one candidate.

Replication found silent MAC-prefix faults in all 24 cases and distance-one
candidates in 3/8, 6/8, and 3/8 cases for the 128-, 192-, and 256-bit profiles.
Every distance-one candidate originated in cube state and affected only the
last tag byte. Four compiler/sanitizer profiles produced byte-identical
replication records; no sanitizer finding or unexpected campaign failure
occurred.

### Interpretation and limitations

The recurrent last-byte relation is consistent with late cube-state faults
remaining latent until the final portion of sequential output, but this
mechanism has not been formally established. The counts apply only to the
registered deterministic inputs and exact software injection point. The work
does not show that an attacker can target, predict, or observe the relevant
state bit, derive the required tag mutation, combine faults, or reproduce the
effect with physical equipment. A bounded negative canonical result is not
evidence of general fault resistance.

### Reproduction

```bash
CXX=g++ ./scripts/run_fault_injection_campaign.sh build-fault-gcc
build-fault-gcc/pvc-rotsymenc1-fault-injection-campaign --localize
build-fault-gcc/pvc-rotsymenc1-fault-injection-campaign --replicate
```

See `FAULT_INJECTION_CAMPAIGN.md`, `FAULT_INJECTION_LOCALIZATION.md`, and
`FAULT_INJECTION_REPLICATION.md` for the pre-registered definitions, complete
measurements, and limitations.

## 2026-08-16: Nonce reuse and allocator rollback

### Classification

Reproduction of a specified full-construction misuse consequence and an
operational state-management warning. This is not a new attack in the
nonce-respecting security model, and the allocator prototype is not part of
the candidate construction.

### Question

Can the known same-key/same-nonce confidentiality loss be reproduced through
the canonical wrapper, and do process crashes, concurrent callers, or restored
snapshots cause an analysis-only persistent counter to repeat returned nonces?

### Method and parameters

Campaign version 1 used seed `0x4E4F4E43454D4754`, a 96-byte nonce-reuse pair,
65,536 simulated 192-bit nonces, a 24-bit collision control, 257 restart
allocations, four injected process-crash points, eight processes making 1,024
allocations, and an eight-allocation snapshot branch. GCC 14.2 and Clang 19.1
Release outputs were compared byte for byte; Clang ASan and UBSan were also run.

### Result

Same-key/same-nonce encryption reproduced the plaintext XOR relation over all
96 bytes while both tags remained valid. Normal restart, injected process
termination, and multi-process allocation produced no reuse of a nonce already
returned to a caller. Restoring the state snapshot repeated all eight nonces
allocated after that snapshot; a detector whose state was not restored caught
all eight. No unexpected campaign or sanitizer finding occurred within the
tested model.

### Interpretation and limitations

The XOR result confirms the documented requirement that a nonce never repeat
under `K_enc`; authentication does not repair that confidentiality loss. The
persistent counter addresses tested normal restart and process-concurrency
cases, but it cannot independently detect rollback or cloned state. Process
termination is not sudden power loss, `/tmp` was a local `tmpfs`, and network
filesystems, dishonest storage, VM clones, and cross-host allocation were not
tested. A bounded collision simulation is not evidence of global collision
freedom or random-generator quality.

### Reproduction

```bash
CXX=g++ ./scripts/run_nonce_misuse_campaign.sh build-nonce-misuse-gcc
CXX=clang++ ./scripts/run_nonce_misuse_campaign.sh build-nonce-misuse-clang
```

See `NONCE_MISUSE_CAMPAIGN.md` and the retained raw records for the complete
method, sanitizer commands, and limitations.

## 2026-08-16: Secret-key-dependent C1 timing

### Classification

Confirmed implementation-side timing leakage evidence on the tested x86-64
host. This is a side-channel observation, not a demonstrated key-recovery
attack, forgery, or break of the abstract full construction.

### Question

Does the current C1 implementation, and the M1/A1/RotSymEnc operations that use
it, show input-content-dependent execution time? In particular, does a signal
remain when the public StreamFrame is identical and only the secret key varies?

### Method and parameters

The official dudect header at commit `dc269651fb2567e46755cfb2a13d3875592968b5`
measured x86 TSC cycles on one pinned logical CPU. Each target used one discarded
12,000-measurement warm-up batch and three 12,000-measurement statistic batches,
balanced classes, 32-byte AD, 64-byte payloads, and 256-bit tags. GCC 14.2 and
Clang 19.1 Release builds were tested. Positive targets were repeated with a
second deterministic seed.

### Result

C1 crossed dudect's `|t| > 10` threshold under both seeds and compilers. In the
minimal key-only test, where the public StreamFrame was byte-identical, maximum
absolute t-statistics ranged from 102.54 to 154.16. The frame-only control was
also positive. The composite M1 tag generation, seal, failed open, and successful
open classes showed repeatable or dual-compiler timing separation. The isolated
M1 first-versus-last tag-mismatch position remained below threshold (`2.87` GCC,
`2.30` Clang).

### Interpretation and limitations

The key-only result is evidence that the current binary's execution time
depends on secret key content. Secret-derived C1 state selects coordinates,
axes, rotation amounts, branches, and memory locations, providing a structural
explanation. No practical key extraction, remote timing attack, or leakage-rate
estimate was attempted. Results remain CPU/compiler/OS dependent, and a
negative dudect result would not prove constant-time behavior. The composite
targets use C1, so their separation is consistent with propagation of the C1
behavior, but those classes do not establish that C1 is their only timing source.

### Reproduction

```bash
CXX=g++ ./scripts/run_timing_characterization.sh build-timing-gcc
CXX=clang++ ./scripts/run_timing_characterization.sh build-timing-clang
```

Full measurements and environment limitations are in
`TIMING_CHARACTERIZATION.md`.

## 2026-08-16: C1 on the Candidate A1 StreamFrame domain

### Classification

Bounded negative campaign. No attack or distinguisher was found at the tested
bounds. Untested keys, inputs, subspaces, and larger campaigns remain
inconclusive; the result does not establish that the hypotheses are globally
false.

### Question

Do valid structured `StreamFrame(N, i, t)` inputs expose full output merging,
related-input differential bias, output bias, or affine output components that
were hidden by C1's general-message campaigns?

### Method and parameters

The standalone audit used the canonical A1 frame writer and frozen C1 entry
point, seed `0x53545245414D4631`, 4,096 samples per stratum, all three tag
profiles, and two exact 12-variable Walsh trials in each of three domain
strata. GCC 14.2.0 and Clang 19.1.7 produced identical measurements. A second
seed, `0x53545245414D4632`, explored a same-direction primary Walsh extreme.

### Result

Both seeds produced zero defined alarms: no equal related outputs, census or
subspace collision, or affine output bit. The primary maximum candidate
absolute bit z-score was 3.4375. The initially same-direction global Walsh
maxima did not repeat under the second seed.

### Interpretation and limitations

The tested bounded hypotheses did not yield an attack. This is not a
full-construction attack, a proof of C1 pseudorandomness, or evidence for a
specific achieved security strength. The structured observations are not
independent Bernoulli samples, and the exact Walsh results cover only six
4,096-point subspaces.

### Reproduction

```bash
CXX=g++ ./scripts/run_streamframe_domain_audit.sh build-streamframe-gcc
CXX=clang++ ./scripts/run_streamframe_domain_audit.sh build-streamframe-clang
```

See `STREAMFRAME_DOMAIN_ANALYSIS.md` and the retained raw records for the full
measurement set.

# Known Cryptanalysis and Current Evidence

PVC-RotSymEnc-1 adds no new cryptographic transform beyond frozen Candidate A1, so its cryptanalytic evidence is inherited from the three component projects plus wrapper-conformance work.

## PVC-PRF-1 Candidate C1

The public C1 package reports bounded differential, linear, algebraic, related-key, joint key/message, return-pass and statistical campaigns. Those results reject specific tested weaknesses only; they do not prove PRF security.

## PVC-MAC-0 Candidate M1

M1 is an injectively framed PRF-as-MAC composition with a conditional reduction to C1. Its public freeze includes independent wrapper reproduction and 4,096 differential tuples. Its security cannot exceed C1's actual security.

## PVC-AEAD-0 Candidate A1

A1 composes a C1 nonce/counter keystream with M1 using Encrypt-then-MAC, independent role keys and verify-before-decrypt. Its public freeze includes structural frame arguments, independent wrapper reproduction, 4,096 differential tuples and tamper-rejection campaigns.

## Known nonce-reuse failure

A1, and therefore PVC-RotSymEnc-1, is not nonce-misuse resistant. Under the same encryption key and nonce, equal counter positions repeat the keystream, yielding the standard XOR relation between plaintext prefixes.

## Wrapper-specific status

The current RotSymEnc draft is required to be byte-exactly equivalent to A1. Wrapper-level testing therefore targets conformance drift, role/tag-profile confusion and API semantics rather than introducing a new cryptanalytic claim.

## StreamFrame-domain campaign

The version-1 StreamFrame campaign tested 49,152 related-input pairs, 12,288
same-key census outputs, and six exact 4,096-point Walsh subspaces across the
three tag profiles. The primary seed produced no full output equality or
collision, no affine output bit, and no absolute per-bit z-score above 3.4375.
An exploratory second seed did not reproduce a same-direction global Walsh
maximum observed in the primary run. This is a bounded negative result, not a
C1 PRF-security argument. Full parameters and limitations are recorded in
`STREAMFRAME_DOMAIN_ANALYSIS.md`.

## Timing leakage observation

The current C1 implementation uses secret-derived coordinates, axes, rotation
amounts, branches, and memory accesses. A pinned dudect campaign on an Intel
i7-10710U found repeatable fixed-versus-random timing separation under GCC 14.2
and Clang 19.1. Key-only localization kept the public StreamFrame identical and
still crossed the `|t| > 10` threshold in both seeds and compilers, with maximum
absolute t-statistics from 102.54 to 154.16. Composite M1 tag generation, seal,
failed open, and successful open classes also showed timing separation. Because
those classes vary multiple inputs, they do not isolate C1 as the sole source;
their results are consistent with propagation through operations that use C1.

This is empirical implementation-side leakage evidence, not a demonstrated
key-recovery attack, remote exploit, or full cryptographic break. The isolated
M1 first-versus-last tag-mismatch test remained below threshold in both
compilers. See `TIMING_CHARACTERIZATION.md`.

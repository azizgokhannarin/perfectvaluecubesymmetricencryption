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

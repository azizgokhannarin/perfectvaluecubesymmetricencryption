# PVC-RotSymEnc-1 Public Cryptanalysis Challenge

PVC-RotSymEnc-1 is an experimental public profile over frozen PVC-AEAD-0 Candidate A1. The purpose of this repository is to make the full symmetric-encryption path easy to reproduce, inspect, falsify, and compare.

## What counts as a useful finding

High-value findings include any reproducible result that demonstrates one of the following:

- **RSE-C1 — conformance break:** two conforming-looking implementations produce different bytes for the same normative tuple;
- **RSE-C2 — wrapper drift:** PVC-RotSymEnc-1 produces output different from frozen Candidate A1;
- **RSE-C3 — role confusion:** an unanticipated relation between `K_enc` and `K_mac` invalidates the documented composition boundary;
- **RSE-C4 — nonce/domain failure:** distinct admissible nonce/counter/tag-profile tuples reuse a keystream block without violating the stated nonce contract;
- **RSE-C5 — authentication gap:** nonce, AD, ciphertext, or tag-profile modifications can be accepted without forging the underlying M1 tag;
- **RSE-C6 — profile confusion:** a 128/192/256-bit tag crosses profile boundaries contrary to the frozen domain binding;
- **RSE-C7 — parsing/length ambiguity:** distinct admissible public tuples reach the same frozen cryptographic input because of a wrapper-level encoding ambiguity;
- **RSE-C8 — underlying break:** a practical distinguisher, state-recovery, key-recovery, forgery, confidentiality break, or other structural attack against C1, M1, or A1 within their documented threat models.

## Known failure mode, not a challenge result

Reusing a nonce under the same encryption key repeats the keystream. The resulting XOR leakage is documented and tested. Reproducing it under deliberate nonce reuse confirms the known misuse behavior; it is not a new break.

## Reporting discipline

Please include:

- exact repository version and candidate identifiers;
- compiler/interpreter and build flags;
- complete keys/nonces/AD/messages or a deterministic generator;
- exact commands;
- sample size and search budget;
- raw output or a minimal reproducer;
- whether the observation concerns this public wrapper or an underlying frozen component.

A negative bounded campaign is useful when its domain and budget are explicit, but it is not a security proof.

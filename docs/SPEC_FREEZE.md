# Specification Freeze Policy

`PVC-RotSymEnc-1 v0.1.0-draft` is a draft public profile over a cryptographically frozen Candidate A1.

## Changes allowed without a new cryptographic candidate

- prose clarification that does not change bytes;
- build-system portability;
- additional tests and audit tools;
- equivalent APIs that map exactly to the normative tuple;
- documentation, citations, packaging, CI and reproducibility improvements.

## Changes that require a new candidate identifier

Any change to:

- C1, M1, or A1 algorithm bytes;
- key sizes or role semantics;
- nonce size or nonce contract;
- StreamFrame or AuthContext bytes;
- counter start, width, endian order, or iteration;
- plaintext-to-keystream XOR behavior;
- Encrypt-then-MAC order;
- what is authenticated;
- tag computation, truncation, or tag-profile binding;
- length limits that alter the admissible cryptographic domain.

A security finding may justify reopening the candidate. Convenience or an unmotivated desire to add more mixing does not.

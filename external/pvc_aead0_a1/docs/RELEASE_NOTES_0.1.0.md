# PVC-AEAD-0 v0.1.0 Release Notes

Initial experimental bootstrap:

- C1 nonce+counter keystream;
- Candidate M1 encrypt-then-MAC;
- independent 256-bit encryption and authentication keys;
- fixed 192-bit nonce;
- 128/192/256-bit domain-separated tag profiles;
- verify-before-decrypt API;
- 48-vector KAT corpus;
- nonce-reuse failure demonstration;
- initial threat model, reduction rationale, and assurance matrix.

This release is not a frozen candidate.

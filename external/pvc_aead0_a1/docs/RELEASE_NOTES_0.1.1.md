# PVC-AEAD-0 v0.1.1 Release Notes

This is a proof, boundary, and test-coverage revision. The AEAD construction, frame bytes, dependency snapshots, and retained 48-vector corpus are unchanged from v0.1.0.

Added:

- primary canonical vector with distinct encryption and authentication key values;
- explicit exclusion of equal, related, or otherwise correlated key roles from the reduction;
- structural injectivity proof for `StreamFrame` and `AuthContext`;
- proof that the two frame families are disjoint;
- expanded nonce-respecting encrypt-then-MAC reduction;
- exact payload, associated-data, and counter limits;
- canonical-vector, maximum-counter, frame-family, and injectivity-witness regression tests.

The all-zero equal-key v0.1.0 vector is retained only as a construction-regression diagnostic and is explicitly outside the supported key-management profile.

This release is not Candidate A1 and is not production cryptography.

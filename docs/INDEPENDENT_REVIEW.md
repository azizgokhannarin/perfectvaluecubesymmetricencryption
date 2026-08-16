# Independent Review Workflow

1. Check out the frozen `v0.1.0-draft-review.1` snapshot.
2. Read `PUBLIC_REVIEW.md` and the known findings before designing a campaign.
3. Read `SPECIFICATION.md` without using `src/symmetric_encryption.cpp` as the specification.
4. Verify the root, profile, and vendored Candidate A1 manifests.
5. Build and run all CTest cases.
6. Reproduce the canonical independent-key vector.
7. Compare PVC-RotSymEnc-1 outputs with Candidate A1 for diverse binary tuples.
8. Confirm authentication failures for modified nonce, AD, ciphertext and tag.
9. Confirm that plaintext is not returned on authentication failure.
10. Inspect nonce-reuse behavior and verify that it matches the documented failure mode rather than an undocumented property.
11. Separate wrapper/profile findings from attacks on C1, M1, or A1.
12. Publish exact inputs, commands and budgets for any claimed result.

The repository's equivalence tests prove only implementation identity within their tested domain; they do not prove cryptographic security.

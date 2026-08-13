# Independent Review Workflow

1. Read `SPECIFICATION.md` without using `src/symmetric_encryption.cpp` as the specification.
2. Verify the vendored Candidate A1 manifests.
3. Build and run all CTest cases.
4. Reproduce the canonical independent-key vector.
5. Compare PVC-RotSymEnc-1 outputs with Candidate A1 for diverse binary tuples.
6. Confirm authentication failures for modified nonce, AD, ciphertext and tag.
7. Confirm that plaintext is not returned on authentication failure.
8. Inspect nonce-reuse behavior and verify that it matches the documented failure mode rather than an undocumented property.
9. Separate wrapper/profile findings from attacks on C1, M1, or A1.
10. Publish exact inputs, commands and budgets for any claimed result.

The repository's equivalence tests prove only implementation identity within their tested domain; they do not prove cryptographic security.

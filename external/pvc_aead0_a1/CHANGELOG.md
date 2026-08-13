# Changelog

## 0.2.0 — 2026-08-02

- Froze the unchanged composition as PVC-AEAD-0 Candidate A1.
- Added an independent AEAD wrapper written from the specification.
- Used Candidate M1's independent MAC wrapper in the second path.
- Added 48-vector independent KAT reproduction.
- Added a 4,096-case differential corpus and cross-open/tamper comparisons.
- Added Candidate A1 freeze, independence, differential, and manifest documents.

## 0.1.1 — 2026-08-02

- Preserved the v0.1.0 construction and dependency snapshots.
- Replaced the primary all-zero/equal-key example with an independent-role KAT.
- Added structural frame injectivity and frame-family separation proofs.
- Expanded the conditional encrypt-then-MAC reduction.
- Defined exact payload, associated-data, and counter bounds.
- Added four focused regression tests.

## 0.1.0 — 2026-08-02

Initial PVC-AEAD-0 experimental composition release.

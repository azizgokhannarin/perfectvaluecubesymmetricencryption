# Changelog

## 0.2.0 — 2026-08-02

- Froze the unchanged construction as PVC-MAC-0 Candidate M1.
- Added a second MAC-wrapper implementation written from the specification.
- Reproduced all 48 retained KAT vectors with both wrappers.
- Added a 4,096-case differential corpus comparing frame, full C1 output, tag, and verification.
- Added a bounded integration/API-misuse audit.
- Documented the framed-input subdomain assumption and its empirical limitation.
- Added the Candidate M1 freeze document, reproducibility script, and manifests.
- Changed no canonical frame byte, C1 parameter, tag value, or truncation rule.

## 0.1.1 — 2026-08-02

- Added a structural proof of canonical-frame injectivity.
- Added the conditional PRF-as-MAC security reduction and explicit security ceiling.
- Documented unsupported-length rejection, u64/size_t limits, allocation failures, and timing boundaries.
- Added verification tests for all supported profiles, an invalid-length matrix, and cross-profile prefix rejection.
- Retained the v0.1.0 construction, API, C1 snapshot, KATs, and 48-vector corpus byte-for-byte.


## 0.1.0 — 2026-08-01

- Established the PVC-MAC-0 experimental repository.
- Added canonical injective framing and tag-size domain binding.
- Added 128-, 192-, and 256-bit tag profiles.
- Added constant-content-time tag comparison.
- Vendored and fingerprinted PVC-PRF-1 Candidate C1 v0.9.0.
- Added 20 CTest checks, 48 canonical vectors, framing audit, and avalanche baseline.

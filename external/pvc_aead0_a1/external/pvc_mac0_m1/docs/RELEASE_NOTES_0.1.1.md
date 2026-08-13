# PVC-MAC-0 v0.1.1 Release Notes

Documentation and verification closure release.

- Added a one-page structural proof that canonical framing is injective.
- Added the conditional PRF-as-MAC reduction and the `min(C1 security, t)` ceiling.
- Documented invalid public tag-length rejection and input-size exception semantics.
- Added tests covering all supported tag lengths, multiple invalid lengths, and cross-profile prefix rejection.
- Changed no construction bytes, primitive parameters, public API, C1 source, KAT, or vector-corpus value.

This remains experimental research software and is not a frozen candidate or production cryptography.

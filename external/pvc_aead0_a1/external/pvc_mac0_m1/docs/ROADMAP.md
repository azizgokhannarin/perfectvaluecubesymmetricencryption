# PVC-MAC-0 Roadmap

## v0.1.0 — construction bootstrap

- canonical frame,
- C1 vendored dependency,
- 128/192/256-bit tag profiles,
- content-independent verification comparison,
- KATs and initial framing/avalanche tools.

## v0.1.1 — documentation and verification closure

- structural frame-injectivity proof,
- conditional PRF-as-MAC reduction,
- explicit security ceiling and unsupported claims,
- public-length and exception semantics,
- all-profile verification and cross-profile rejection tests.

## v0.2.0 — Candidate M1 freeze

- explicit framed-input subdomain limitation,
- independent specification wrapper,
- independent reproduction of 48 retained KATs,
- 4,096-case binary differential corpus,
- bounded integration/API-misuse audit,
- GCC/Clang/sanitizer verification,
- frozen candidate manifest and change rule.

## Post-freeze work

- external review and cryptanalysis;
- publication/reproducibility packaging;
- protocol integration guidance;
- a separate PVC-AEAD project that pins Candidate M1 rather than modifying it.

No additional mixer, round, key schedule, or bespoke truncation transform is planned. Candidate M1 changes only in response to a demonstrated specification, construction, interoperability, or material API defect.

# PVC-MAC-0 Candidate M1 Freeze — v0.2.0

## Frozen identity

- Candidate name: **PVC-MAC-0 Candidate M1**
- Release version: **0.2.0**
- Freeze date: **2026-08-02**
- Dependency: **PVC-PRF-1 Candidate C1 / v0.9.0**
- Key size: **256 bits**
- Tag profiles: **128, 192, and 256 bits**

## Frozen construction

```text
Tag_t(K,C,M) = Prefix_t(C1_K(Frame(C,M,t)))
```

The following are frozen for Candidate M1:

- the exact 30-byte frame header and field offsets;
- U64BE context and message length encoding;
- construction, frame-version, and C1 profile identifiers;
- tag-length domain binding;
- use of the unmodified frozen C1 primitive;
- prefix truncation to 16, 24, or 32 bytes;
- supported-length verification behavior;
- dedicated-key rule and documented context semantics.

## Freeze gate completed

- structural frame-injectivity proof;
- conditional PRF-as-MAC reduction;
- explicit framed-subdomain assumption;
- 48/48 KAT reproduction by both wrappers;
- 4,096/4,096 wide differential cases;
- frame, full-output, tag, and verification agreement;
- bounded integration/API-misuse audit;
- GCC, Clang, ASan, and UBSan build/test verification;
- pinned C1 and repository manifests;
- reproducible differential corpus.

## Frozen fingerprints

```text
Bit-exact specification:
167a11cbeb5ef802a8ba66d4d82c9053460c9610c1b2e64f14b03f253dc5caa6

Canonical wrapper source:
a8e5889144780c4ab1f4636239387e4a3bb3be003fecbe3126cfe08c598891cb

Independent wrapper source:
d9482069dffd5fe4b1787569420585f7f2af4bd01f3883a2c9f4d0a6dd6158c8

Retained 48-vector KAT corpus:
482b36274d940c1279a69b47c9254bbcfb1fb1c821c2dfacce39441fb9cca1ea

Candidate M1 4,096-case differential corpus:
941fddaf40f82bcf7929d7be1a9f396676bd75b1e7496e9c2594e6aa408078d6

Vendored C1 source manifest:
6321a101516bea1766e8192ab64df62431dbaa667115ee9697f14c66c952aeb2
```

## Change rule

Candidate M1 must not receive additional mixers, rounds, key schedules, truncation transforms, or silent frame changes.

A new MAC candidate is justified only if external review identifies:

- a specification ambiguity;
- an encoding collision;
- a reproducible implementation disagreement;
- a construction-level forgery not attributable solely to a break of C1;
- or a material API defect requiring wire-format or verification changes.

A structural break of C1 belongs to the PRF project and cannot be patched inside Candidate M1.

## Status boundary

Candidate M1 is a frozen experimental research candidate suitable for publication, reproducibility work, and external cryptanalysis. It is not proven secure, production-ready, standardization-ready, or assigned a quantified classical or post-quantum security level.

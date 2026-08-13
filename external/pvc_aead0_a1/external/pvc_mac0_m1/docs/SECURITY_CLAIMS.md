# PVC-MAC-0 Candidate M1 / v0.2.0 Security Claims

## Supported statements

- The canonical encoder is injective on the documented supported-length domain; see `FRAME_INJECTIVITY_PROOF.md`.
- Context, message, primitive profile, frame version, and requested tag length are bound to the C1 input.
- The implementation accepts only 128-, 192-, and 256-bit tag profiles.
- For supported lengths, verification compares every supplied byte without content-dependent early exit.
- Unsupported public tag lengths are rejected before C1 evaluation.
- The vendored C1 algorithm files are pinned and independently fingerprinted.
- A second wrapper implementation was written from the specification without including or linking the canonical wrapper.
- Both wrapper implementations matched on the 48 retained KAT vectors and 4,096 deterministic randomized binary cases at the frame, full-output, truncated-tag, and verification layers.
- Bounded integration tests cover repartitioning, embedded zero bytes, extension boundaries, wrong key/context/message, tag mutation, invalid public lengths, and cross-profile prefix rejection.

## Conditional reduction statement

Under the standard PRF-as-MAC argument, PVC-MAC-0 is a candidate MAC if PVC-PRF-1 Candidate C1 is a secure PRF on the canonical framed-input domain.

For a `t`-bit tag profile and at most `q_v` independent online verification attempts, the conventional qualitative bound is:

```text
Adv_forge <= Adv_prf(C1) + q_v / 2^t.
```

The effective security is bounded above by both the actual security of C1 and the selected tag length. This is summarized as `min(C1 security, t)` and is not a claim that C1 achieves a particular bit-security level.

The complete reduction statement and assumptions are in `SECURITY_REDUCTION.md`.

## Framed-input subdomain limitation

All valid PVC-MAC-0 inputs to C1 share a structured 30-byte header and then contain explicit context and message lengths. The reduction therefore assumes that C1 behaves as a PRF on this structured framed-input subdomain.

A secure PRF must remain secure on such a subdomain, so this is not a composition defect. However, Candidate C1's bounded cryptanalytic campaigns were not designed as a dedicated attack campaign against the exact PVC-MAC-0 framed-input distribution. The independent differential campaign validates implementation agreement, not cryptographic pseudorandomness on that subdomain.

## Implementation boundary

The tag comparison loop is content-independent for supported lengths. The complete MAC computation is not claimed to be constant-time because C1 uses data-dependent memory access. Input-length and allocation failures are documented in `API_BEHAVIOR.md`.

## Not claimed

- proven MAC security,
- proven PRF security for C1,
- 128-, 192-, or 256-bit effective security,
- dedicated cryptanalysis of the complete framed-input subdomain,
- resistance to all classical or quantum attacks,
- constant-time C1 execution,
- fault or side-channel resistance,
- production readiness,
- standardization readiness.

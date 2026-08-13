# PVC-MAC-0 Candidate M1 Design Rationale

## Goal

Define the smallest auditable MAC layer over the frozen PVC-PRF-1 Candidate C1 primitive without changing C1 or embedding an unrelated cryptographic primitive.

## Construction choice

PVC-MAC-0 uses a direct PRF-MAC construction:

```text
Tag_t(K,C,M) = Prefix_t(C1_K(Frame(C,M,t)))
```

This construction adds only:

1. an injective frame,
2. MAC-specific domain separation,
3. tag-length domain binding,
4. content-independent tag comparison.

No hash function, block cipher, standard KDF, standard S-box, or external MAC primitive is embedded in the construction.

## Why tag length is framed

A request for a 128-bit tag and a request for a 256-bit tag are different domains. A prefix from the 256-bit profile is not automatically valid in the 128-bit profile.

## Why context exists

The context field lets a protocol bind a tag to a purpose such as `firmware-manifest`, `license-record`, or a protocol/version identifier. Applications should use a stable, non-empty context and a key dedicated to PVC-MAC-0.

## Frozen dependency rule

Candidate M1 must not modify the vendored C1 sources. A C1 change requires a separately versioned PRF candidate and an explicit dependency migration to a new MAC candidate.

## Why no additional MAC mixing exists

Any MAC-specific round, mixer, key schedule, or bespoke truncation transform would create a new cryptographic component and invalidate the simple PRF-as-MAC reduction. PVC-MAC-0 deliberately remains a thin encoding and verification layer.

## Independent implementation rule

The Candidate M1 second implementation re-implements only the MAC wrapper and shares the frozen C1 primitive. This is sufficient to test whether the MAC specification uniquely determines frame bytes, truncation, and verification. It is not represented as a second independent C1 implementation.

## Formal support documents

- `FRAME_INJECTIVITY_PROOF.md`: structural injectivity argument.
- `SECURITY_REDUCTION.md`: conditional PRF-as-MAC reduction and framed-subdomain assumption.
- `INDEPENDENT_IMPLEMENTATION.md`: independence boundary.
- `DIFFERENTIAL_VERIFICATION.md`: exact comparison campaign.
- `API_BEHAVIOR.md`: public-length rejection and exception behavior.

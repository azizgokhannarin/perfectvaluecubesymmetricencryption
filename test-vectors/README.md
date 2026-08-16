# Test vectors

This draft retains the frozen Candidate A1 vector material unchanged:

- `PVC_AEAD0_VECTORS_0.1.0.csv` — 48 KAT vectors;
- `PVC_AEAD0_DIFFERENTIAL_A1.csv` — 4,096-case independent Candidate A1 differential corpus.
- `cross-platform-conformance-v1.json` — versioned SHA-256 fingerprint and
  parameters for the deterministic 4,096-case RotSymEnc transcript used by the
  portability matrix. SHA-256 is an external test fingerprint only and is not
  part of the construction.

PVC-RotSymEnc-1 is normatively byte-equivalent to A1, so these are also conformance anchors for this draft profile.

The cross-platform fingerprint is a conformance artifact. It must not be
silently regenerated when a platform differs; first determine whether the
implementation, transcript generator, or specification is wrong.

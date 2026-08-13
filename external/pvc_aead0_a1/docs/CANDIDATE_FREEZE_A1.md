# PVC-AEAD-0 Candidate A1 Freeze — v0.2.0

## Frozen identity

- Candidate name: **PVC-AEAD-0 Candidate A1**
- Release version: **0.2.0**
- Freeze date: **2026-08-02**
- Encryption dependency: **PVC-PRF-1 Candidate C1 / v0.9.0**
- Authentication dependency: **PVC-MAC-0 Candidate M1 / v0.2.0**
- Key profile: two independently generated 256-bit keys
- Nonce: 192 bits, unique under each encryption key
- Tag profiles: 128, 192, and 256 bits

## Frozen construction

```text
Z_i = C1_Kenc(StreamFrame(N,i,t))
C   = P XOR Z
A   = AuthContext(N,AD,t)
T   = M1_Kmac(A,C,t)
Open verifies T before deriving or returning P.
```

The following are frozen for Candidate A1:

- StreamFrame and AuthContext bytes and field offsets;
- stream/authentication role-domain separation;
- big-endian 64-bit counter and associated-data length encoding;
- 32-byte C1 keystream block schedule starting at counter zero;
- encrypt-then-MAC sequencing;
- authentication of nonce, AD, ciphertext, and tag profile;
- independent encryption/authentication key roles;
- 192-bit nonce profile and nonce-uniqueness contract;
- 16-, 24-, and 32-byte tag profiles;
- verify-before-decrypt behavior;
- documented payload, context, and counter bounds;
- unmodified frozen C1 and Candidate M1 dependencies.

## Freeze gate completed

- structural injectivity proofs for both frame families;
- frame-family disjointness proof;
- conditional nonce-respecting Encrypt-then-MAC reduction;
- exact key-separation and nonce requirements;
- exact payload and counter bounds;
- 48/48 KAT reproduction by both AEAD wrappers;
- 4,096/4,096 differential tuples;
- frame, used-keystream, ciphertext, auth-context, tag, and cross-open agreement;
- bounded tag/nonce/AD/ciphertext rejection comparisons;
- GCC, Clang, ASan, and UBSan build/test verification;
- pinned dependency, source, candidate, and vector manifests.

## Frozen fingerprints

Fingerprints are recorded in `CANDIDATE_MANIFEST.SHA256` and the release
verification report. They cover the bit-exact specification, canonical and
independent wrappers, retained KAT corpus, Candidate A1 differential corpus,
and frozen dependency manifest.

## Change rule

Candidate A1 must not receive additional mixers, rounds, S-boxes, hashes, KDFs,
key schedules, nonce transforms, tag transforms, or silent frame changes.

A new AEAD candidate is justified only if review identifies:

- a specification ambiguity or implementation disagreement;
- a frame collision or counter/length defect;
- a verify-before-decrypt or authentication-coverage failure;
- a composition attack not attributable solely to a break of C1 or M1;
- or a material API defect requiring wire-format or security-semantics changes.

A structural break of C1 belongs to the PRF project. A construction-level break
of M1 belongs to the MAC project. Neither dependency may be silently patched
inside Candidate A1.

## Status boundary

Candidate A1 is a frozen experimental research candidate suitable for
publication, reproducibility work, and external cryptanalysis. It is not proven
secure, nonce-misuse-resistant, production-ready, standardization-ready, or
assigned a quantified classical or post-quantum security level.

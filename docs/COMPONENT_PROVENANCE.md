# Component Provenance

PVC-RotSymEnc-1 v0.1.0-draft is defined over the following frozen public research components.

| Layer | Frozen identifier | Public repository |
|---|---|---|
| PRF | PVC-PRF-1 Candidate C1 / v0.9.0 | https://github.com/azizgokhannarin/PVC-PRF-1 |
| MAC | PVC-MAC-0 Candidate M1 / v0.2.0 | https://github.com/azizgokhannarin/PVC-MAC-0 |
| AEAD | PVC-AEAD-0 Candidate A1 / v0.2.0 | https://github.com/azizgokhannarin/PVC-AEAD-0 |

The repository vendors the exact Candidate A1 source snapshot under `external/pvc_aead0_a1/`. That tree recursively contains the pinned M1 and C1 snapshots used by A1.

Local source-package fingerprints used to bootstrap this repository:

```text
PVC-PRF-1 publication-prep v0.9.0 ZIP:
bfbc74ecabdd59ed5430f1fcbf7bfe9db048607fd47320ee0923c3319c2786bb

PVC-MAC-0 Candidate M1 v0.2.0 ZIP:
6094d4f80f48f4d5c7af75641c250782e9f783c1d3cfe81ffd0bccf388bcc15c

PVC-AEAD-0 Candidate A1 v0.2.0 ZIP:
c1d156b0b7af1b35e791aa9f9ecae54e38ee592da0a576e7c29a40fccefe8596
```

These ZIP fingerprints describe the local bootstrap artifacts. The vendored tree also retains Candidate A1's own `SOURCE_MANIFEST.SHA256`, `DEPENDENCY_MANIFEST.SHA256`, and `CANDIDATE_MANIFEST.SHA256` files.

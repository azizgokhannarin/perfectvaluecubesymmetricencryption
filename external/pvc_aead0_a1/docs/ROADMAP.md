# PVC-AEAD-0 Roadmap

## v0.1.0 — composition bootstrap

- C1 nonce+counter stream;
- Candidate M1 encrypt-then-MAC;
- nonce, AD, ciphertext and tag-profile binding;
- initial KAT, framing and tamper campaigns.

## v0.1.1 — proof and boundary closure

- independent-key canonical vector;
- explicit equal/related-key exclusion;
- structural injectivity proof for both frame families;
- conditional encrypt-then-MAC reduction;
- exact payload, AD and counter limits;
- counter-boundary and role-separation regressions.

## v0.2.0 — Candidate A1 freeze

- independent AEAD wrapper from the specification;
- independent Candidate M1 wrapper in the second composition path;
- 48/48 independent KAT reproduction;
- 4,096-case deterministic differential corpus;
- frame, used-keystream, ciphertext, AuthContext, tag, and cross-open agreement;
- bounded two-wrapper tamper comparisons;
- candidate manifests and reproducibility package.

## Post-freeze work

Candidate A1 is not to be strengthened through ad hoc new mixing. Remaining work is publication, independent external review, protocol integration analysis, and cryptanalysis. A new candidate version is opened only for a concrete specification, composition, or security defect.

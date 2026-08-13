# Security Target and Explicit Non-Claims

## Intended research target

Under independent uniformly generated role keys, nonce uniqueness, the frozen length profile, and the documented threat model, PVC-RotSymEnc-1 targets nonce-respecting authenticated encryption by inheriting Candidate A1's conditional construction argument.

Informally, the composition seeks:

- plaintext confidentiality from the C1-derived nonce/counter keystream;
- ciphertext integrity and binding of nonce/AD/tag-profile from Candidate M1;
- authenticated encryption through verify-before-decrypt Encrypt-then-MAC composition.

## Conditionality

All cryptographic uncertainty is inherited from the frozen components. In particular, the profile does not prove that Candidate C1 is a secure PRF.

## Explicit non-claims

PVC-RotSymEnc-1 does not claim:

- proven IND-CPA, IND-CCA, INT-CTXT, or AEAD security;
- 128-, 192-, or 256-bit end-to-end security merely because those tag sizes exist;
- quantified post-quantum security;
- nonce-misuse resistance;
- side-channel resistance of the full C1 evaluation;
- fault-attack resistance;
- production readiness;
- standards readiness;
- suitability for protecting real data.

The tag size is only one upper bound on generic online forgery probability; actual security cannot exceed the effective security of the underlying frozen components.

# PVC-AEAD-0 Candidate A1 / v0.2.0 Security Claims

## Supported statements

- Candidate A1 is a bit-exact C1-stream plus Candidate M1 encrypt-then-MAC composition.
- Stream and authentication frames are structurally injective under the documented length limits.
- Stream and authentication frame families are role-domain-separated.
- Encryption and authentication keys are separate API values; the reduction requires independent generation.
- Nonce, associated data, ciphertext, and tag profile are authenticated.
- Opening verifies Candidate M1 before deriving or returning plaintext.
- 128-, 192-, and 256-bit tag profiles are domain-separated.
- Payload and authentication-context bounds prevent counter or encoded-length wrap.
- Two independently written AEAD wrappers reproduce all 48 KAT vectors.
- The two wrappers matched in 4,096 deterministic binary differential tuples at frame, used-keystream, ciphertext, authentication-context, tag, and cross-open levels.
- The construction and retained KAT outputs are unchanged from v0.1.1.

## Unsupported statements

Candidate A1 is not claimed to be:

- an unconditionally or formally proven-secure AEAD scheme;
- secure when `K_enc` and `K_mac` are equal, related, or non-independently generated;
- misuse-resistant or safe under nonce reuse;
- production-ready;
- constant-time as a complete computation;
- side-channel- or fault-resistant;
- 128-, 192-, or 256-bit secure merely because of parameter widths;
- formally or quantitatively post-quantum secure;
- standardized or independently cryptanalysed.

## Conditional reduction

Under independent keys, nonce-respecting use, injective framing, admissible lengths, verify-before-decrypt behavior, and the assumed C1/M1 properties, Candidate A1 follows the standard encrypt-then-MAC composition argument described in `SECURITY_REDUCTION.md`.

## Dependency and subdomain inheritance

All unresolved C1 and Candidate M1 limitations are inherited. The confidentiality argument assumes C1 behaves as a PRF on the structured StreamFrame domain. The integrity argument inherits M1's assumption that C1 behaves as a PRF on its framed MAC domain. These structured subdomains have bounded implementation and differential coverage, not a proof of pseudorandomness.

## Meaning of freeze

The Candidate A1 freeze means that the composition is specified unambiguously, independently reimplemented, reproducible, and no longer changing absent a concrete defect. It does not upgrade the evidence level of C1 or M1 and does not establish achieved security strength.

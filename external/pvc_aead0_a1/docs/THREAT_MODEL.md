# PVC-AEAD-0 Candidate A1 / v0.2.0 Threat Model

## Target interface

The adversary may choose plaintexts and associated data, observe nonces, ciphertexts, and tags, and submit modified tuples for opening. The intended security model is nonce-respecting authenticated encryption with associated data.

## Security goals

- confidentiality of plaintext against chosen-plaintext observation under unique nonces;
- rejection of modified nonce, associated data, ciphertext, or tag;
- no plaintext return before successful authentication;
- domain separation among stream, authentication, and tag-size profiles;
- no stream-counter reuse or wrap within admissible messages.

## Public values

Nonce, associated data, ciphertext length, tag length, and algorithm profile are public.

## Required trusted behavior

- independent uniform generation of `K_enc` and `K_mac`;
- nonce uniqueness and persistence under each encryption key;
- enforcement of documented length limits;
- no release or processing of plaintext on authentication failure;
- correct replay policy at the protocol layer.

## Out of scope

- equal, correlated, password-derived, or otherwise weak key pairs;
- nonce-misuse resistance;
- side-channel and fault resistance;
- traffic-analysis resistance or length hiding;
- replay protection;
- master-key derivation;
- production deployment;
- formal or quantified post-quantum security.

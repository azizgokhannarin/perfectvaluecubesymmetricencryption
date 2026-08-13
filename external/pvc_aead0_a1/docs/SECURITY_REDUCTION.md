# PVC-AEAD-0 Candidate A1 / v0.2.0 Conditional Security Reduction

## 1. Scope

This is a conditional composition argument, not a proof that Candidate C1 satisfies the assumed PRF property and not a measured bit-security claim.

The target is nonce-respecting authenticated encryption with associated data. The adversary may choose plaintexts and associated data, observe public nonces, ciphertexts and tags, and submit tuples to `open`. The nonce-respecting game never repeats a nonce in sealing queries under the same encryption key.

## 2. Assumptions

The argument requires all of the following:

1. Candidate C1 is a secure PRF on the structured stream-frame domain under `K_enc`.
2. Candidate M1 is a secure verification MAC on its structured domain under `K_mac`; M1's own reduction is conditional on C1 under that key.
3. `K_enc` and `K_mac` are independently and uniformly generated 256-bit keys.
4. Nonces do not repeat under `K_enc`.
5. The bit-exact frame definitions are followed.
6. `open` authenticates before deriving or returning plaintext.
7. Inputs satisfy the documented length and counter limits.

Exact key equality, related keys, master-key derivation, or any other correlation between `K_enc` and `K_mac` is outside this reduction. The API cannot test statistical independence; this is a key-management requirement.

## 3. Lemma: distinct stream inputs

For each message block, the C1 input is:

```text
StreamFrame(N,i,t).
```

`StreamFrame` is injective in `(N,i,t)`. Counters are distinct within one message, and the nonce contract makes nonces distinct across sealing calls. Therefore no two stream blocks queried under one encryption key use the same C1 input.

The payload bound implies at most `2^59` blocks per message, so the 64-bit counter cannot wrap.

## 4. Confidentiality hybrid

Replace C1 under `K_enc` with a truly random function on the stream-frame domain. The distinguishing loss is the PRF advantage against C1 for the total number of stream-block queries.

Because all stream inputs are distinct, the random-function outputs used as 256-bit pads are independent uniform blocks. XOR with those blocks gives the standard nonce-respecting one-time-pad hybrid for each plaintext block. Associated data is public and does not affect the stream; it is authenticated separately.

Thus, under the nonce contract:

```text
Adv_conf(A)
  <= Adv_prf_C1_stream(B_enc).
```

The notation suppresses the exact time and query translation.

## 5. Integrity reduction

The authenticated value is Candidate M1 over:

```text
context = AuthContext(N,AD,t)
message = C
profile = t.
```

`AuthContext` is injective in `(N,AD,t)`, and Candidate M1 injectively frames `(context,C,t)`. Therefore a newly accepted `(N,AD,C,T)` tuple that was not returned by `seal` yields a successful verification forgery against Candidate M1, except for exact replay, which is a protocol concern rather than a fresh-ciphertext forgery.

For tag length `t` and `q_v` independent verification attempts, Candidate M1's conditional bound has the form:

```text
Adv_int(A)
  <= Adv_prf_C1_mac(B_mac) + q_v / 2^t.
```

This includes the possibility of an alternate valid tag for a previously authenticated tuple.

## 6. Encrypt-then-MAC composition

The encryption and authentication keys are independent, the tag covers the public nonce, associated data, tag profile and exact ciphertext, and `open` verifies before decrypting. The standard encrypt-then-MAC game transition therefore combines the confidentiality and integrity bounds:

```text
Adv_nr-aead(A)
  <= Adv_prf_C1_stream(B_enc)
   + Adv_prf_C1_mac(B_mac)
   + q_v / 2^t,
```

up to the exact authenticated-encryption game definition, running-time translation, query accounting and conventional constant factors.

This formula states where a successful attack must transfer; it does not assign a numerical value to either C1 PRF term.

## 7. Structured-domain limitation

Encryption uses fixed-format 48-byte C1 inputs. Candidate M1 uses its own structured framed inputs. Existing bounded C1 campaigns do not prove PRF security on these complete AEAD-specific distributions or in simultaneous two-key use.

## 8. Security ceiling and exclusions

PVC-AEAD-0 cannot be stronger than:

- Candidate C1 under either key;
- Candidate M1;
- the selected tag length;
- key generation and separation;
- nonce management;
- the implementation environment.

The reduction does not cover nonce reuse, replay, side channels, fault injection, weak or correlated keys, password-derived keys, key compromise, release of unauthenticated plaintext, misuse-resistant security, or quantified post-quantum security.

# PVC-MAC-0 Candidate M1 Conditional Security Reduction

## Construction

Let `F_K : {0,1}* -> {0,1}^256` denote PVC-PRF-1 Candidate C1 under key `K`. Let `E(C,M,t)` denote the canonical PVC-MAC-0 frame, and let `Prefix_t` return the first `t` bits, where `t` is one of 128, 192, or 256.

PVC-MAC-0 is:

```text
MAC_K(C,M,t) = Prefix_t(F_K(E(C,M,t))).
```

The tag length is part of `E`; different tag profiles therefore use different PRF inputs.

## Conditional theorem

If C1 is a secure PRF over the canonical framed-input domain and `E` is injective, then PVC-MAC-0 has the conventional PRF-as-MAC rationale for existential unforgeability under chosen-message attack.

For an adversary making at most `q_v` independent online verification attempts in a `t`-bit tag domain, the standard reduction gives the qualitative bound:

```text
Adv_forge(PVC-MAC-0, t)
    <= Adv_prf(C1) + q_v / 2^t,
```

subject to the exact accounting conventions of the chosen PRF and MAC games. For a single final forgery attempt, the random-function term is `2^-t`.

## Reduction sketch

A distinguisher answers the MAC adversary's authentication queries by forwarding the injectively framed inputs to either:

1. the real keyed C1 function, or
2. a uniformly random function with 256-bit outputs.

If the oracle is C1, the simulation is the real PVC-MAC-0 game. If the oracle is random, injectivity ensures that every fresh `(C,M,t)` tuple maps to a fresh oracle input. Its `t`-bit tag prefix is therefore uniformly distributed, even when the same context and message were queried under a different tag length, because that profile has a different framed input.

A successful fresh forgery in the random-function game consequently requires guessing the relevant `t`-bit value, apart from repeated online attempts already counted by `q_v / 2^t`. Any materially larger advantage transfers to a distinguisher against C1.

## Framed-input subdomain assumption

The theorem requires C1 to behave as a PRF on the image of `E`. That image is a structured subset of C1's arbitrary-length input domain: every frame starts with the same construction identifier and fixed fields, followed by tag-size and two fixed-width lengths.

This is a normal assumption in a PRF composition: a genuine PRF must be pseudorandom on every efficiently recognizable input subset. It is nevertheless an explicit limitation of the empirical evidence. Candidate C1's existing bounded campaigns do not constitute a dedicated cryptanalytic campaign targeting only the PVC-MAC-0 framed-input distribution.

The 4,096-case Candidate M1 differential corpus proves that two implementations agree on the exact framed subdomain. It does not prove that C1 is pseudorandom there.

## Security ceiling

This reduction does not establish that C1 is a secure PRF. PVC-MAC-0 inherits all limitations of Candidate C1. Its effective classical security cannot exceed either:

- the actual security of C1 in the relevant attack model, or
- the selected tag length.

Accordingly, the shorthand ceiling is `min(C1 security, t)`, not an assertion that any particular bit-security level has been achieved.

## Exclusions

This argument does not cover:

- side-channel or fault attacks,
- weak key generation or key reuse across protocols,
- replay protection,
- misuse by accepting unsupported tag lengths,
- a proof or quantified claim of post-quantum security,
- production suitability.

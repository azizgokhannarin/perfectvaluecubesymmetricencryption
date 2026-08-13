# PVC-MAC-0 Candidate M1 Threat Model

## Adversary capabilities

The primary research model allows an adversary to:

- choose contexts and messages,
- obtain valid tags for chosen `(context,message,tag-length)` tuples,
- adapt later queries based on earlier results,
- observe whether a submitted tag verifies,
- know the full construction, source code, framing, and test vectors.

The key remains secret, uniformly sampled over 32 bytes, dedicated to the MAC instance, and unavailable through raw C1 access in the modeled protocol.

## Security target

The target is existential unforgeability under chosen-message attack: produce a valid tag for a fresh `(context, message, tag-length)` tuple. Because tag length is frame-bound, queries in another tag-length profile are distinct oracle inputs.

## Conditional basis

The security rationale assumes that frozen PVC-PRF-1 Candidate C1 behaves as a PRF on the structured canonical frame image. Candidate M1 does not prove this assumption and does not assign a bit-security level to it.

## Stronger research models

External analysis may additionally test:

- related-key relations,
- joint key/message compensation,
- truncated-tag multi-user behavior,
- framed-subdomain distinguishers,
- tag-length cross-domain relations,
- internal C1 structural attacks inherited from the dependency.

Passing a bounded experiment in these stronger models is not a proof.

## Out of scope

- side-channel resistance of C1's data-dependent memory access,
- fault injection,
- key generation and storage,
- nonce misuse because PVC-MAC-0 has no nonce,
- protocol replay prevention,
- production deployment,
- formal or quantified post-quantum security.

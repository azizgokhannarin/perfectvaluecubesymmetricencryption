# PVC-PRF-1 Candidate C1 Freeze — v0.9.0

## Decision

Version 0.9.0 freezes the A2 full pipeline as **PVC-PRF-1 Candidate C1** for
public cryptanalytic review.

The candidate is not standardized, proven secure or suitable for production.
"Freeze" means that future algorithm changes require a new candidate identifier
and new regression vectors; it does not mean that the security question is
closed.

## Frozen candidate parameters

```text
Key size:                    256 bits
Output size:                 256 bits
Controller:                  A2, 128 bits
KeyForward moves/symbol:     4
KeyReturn moves/symbol:      4
KeySeal moves/symbol:        4
Forward message moves/byte:  8
ReturnInit:                  16 symbols × 4 moves
Reverse message:             8 moves/byte
ReturnSeal:                  8 symbols × 4 moves
Finalization:                4 moves/binding byte
Squeeze:                     2 moves/output byte
```

The Perfect Value Cube, domain identifiers, framing equations, controller
updates, amount mapper, return equations, finalization and squeeze are those in
the v0.9.0 source tree and `SPECIFICATION.md`.

## Candidate vector

All-zero 256-bit key and ASCII message `abc`:

```text
7a56cb57bc6d988b1718f62ef637554377e6412790d1f66a57ef6cf0cf9b49c4
```

Return-state fingerprint:

```text
54113b41ef857c59
```

## Prototype B

Prototype B is excluded from Candidate C1. It remains in the repository as an
independent architectural comparator and regression target. Its purpose is to
identify results that accidentally depend on the A2 topology.

## Change control

The following require a new candidate ID:

- any controller equation or constant change;
- amount/axis selector change;
- key framing or domain change;
- movement count change;
- return initialization, reverse framing or seal change;
- finalization or squeeze change;
- output length change.

Documentation, tooling, test expansion and implementation hardening may continue
without changing C1, provided the candidate vectors remain unchanged.

## Explicit non-claims

Candidate C1 does not claim:

- proof of PRF security;
- a 256-bit classical or post-quantum security level;
- resistance to every related-key or chosen-input attack;
- side-channel or fault resistance;
- constant-time implementation;
- production readiness.

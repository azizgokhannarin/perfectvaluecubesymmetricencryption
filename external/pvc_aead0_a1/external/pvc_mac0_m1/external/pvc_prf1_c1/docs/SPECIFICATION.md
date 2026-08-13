# PVC-PRF-1 Candidate C1 Specification — v0.9.0

Version 0.9.0 freezes the A2 complete pipeline as **PVC-PRF-1 Candidate C1** for
public cryptanalytic review. Prototype B remains an independent audit comparator
and is not part of Candidate C1.

This is an experimental candidate specification. It is not a standard, a proof
of security or a production recommendation.

## Candidate identity

```text
Candidate name: PVC-PRF-1-C1
Key size:       256 bits
Output size:    256 bits
Controller:     A2, 128 bits
```

An algorithm or parameter change requires a new candidate identifier and new
vectors. Tooling and documentation may evolve while C1 remains bit-for-bit
unchanged.

## Physical operation

1. The state contains an 8×8×8 Perfect Value Cube whose 512 cells contain two
   occurrences of every byte value.
2. A movement selects an axis different from the previous axis.
3. The eight-cell line through the cursor is rotated by 1..7 cells.
4. The cursor advances by the same amount on that line.
5. Position-sensitive pre/post line data updates controller state.

The cube values are permuted, not replaced. Security state therefore includes
cube position, geometry, controller and transcript; the cube alone is not the
complete state.

## A2 controller state

```text
axis_control    16 bits
amount_control  16 bits
feedback        32 bits
transcript      64 bits
```

Axis and amount use separate controller/probe paths. Axis is not selected from a
single parity bit. Amount uses a balanced state-derived permutation of 1..7,
not direct reduction modulo seven. Position-sensitive feedback distinguishes
line orderings that have the same byte multiset.

The exact update equations, constants and domain identifiers are fixed by:

```text
include/pvc1/controller.hpp
src/controller.cpp
```

## Key type and initialization

```text
ResearchKey256 = 32 bytes
```

The public bootstrap value is `0x5056433150524631`. The key is not compressed
into that seed or another scalar. Candidate C1 uses three domain-separated
passes:

- `KeyForward`: header, direct framed key bytes and cross-coupled symbols;
- `KeyReturn`: reverse key traversal with independent offsets;
- `KeySeal`: symbols combining both key halves and distant positions.

Frozen profile:

```text
KeyForward moves/symbol = 4
KeyReturn moves/symbol  = 4
KeySeal moves/symbol    = 4
```

The default schedule contains 120 framed symbols and 480 cube movements. Only
the public message symbol counter is reset afterward; cube, geometry,
controller and transcript retain key history.

The exact framing is fixed by `src/key_schedule.cpp`.

## Forward keyed mapping

1. Enter `InputForward` with the message length.
2. Absorb bytes in forward order.
3. Retain complete cube, cursor, previous axis, controller and transcript.

Frozen profile:

```text
Forward message moves/byte = 8
```

## Transcript-derived return

The return is not a direct continuation of the forward controller. It uses a
snapshot of the complete forward state and three separate domains.

Frozen profile:

```text
ReturnInit symbols       = 16
ReturnInit moves/symbol  = 4
Reverse-message moves    = 8 per byte
ReturnSeal symbols       = 8
ReturnSeal moves/symbol  = 4
```

### ReturnInit

The boundary binds:

- forward full-state fingerprint and symbol index;
- message length;
- complete controller and transcript;
- cursor and previous axis;
- state-selected cube probes.

Sixteen state-derived symbols are absorbed in `ReturnInit`.

### InputReturn

Message bytes are traversed in reverse. Every return symbol combines the byte,
reverse position, message length, pre-return controller snapshot and an
evolving current-state cube probe.

### ReturnSeal

A separate domain absorbs eight symbols derived from both the pre-return
snapshot and the post-return state.

The exact equations are fixed by `src/return_pass.cpp`.

## Controller-bound finalization and squeeze

Candidate C1 does not read only cube diagonals. It binds the controller before
producing output.

Frozen profile:

```text
Finalization moves/binding byte = 4
Squeeze moves/output byte       = 2
Output bytes                    = 32
```

Procedure:

1. enter `Finalization` with message-length framing;
2. absorb all 16 A2 controller bytes;
3. enter `Squeeze`;
4. generate each byte from state-selected cube cells and controller bytes;
5. absorb every produced byte before generating the next byte.

The exact equations are fixed by `src/finalization.cpp`.

## Candidate API

The compatibility API name retains the earlier research prefix:

```text
research_keyed_return_output_a2
```

For v0.9.0, this function with default profiles is the bit-exact Candidate C1
mapping.

## Candidate vector

All-zero 256-bit key and ASCII message `abc`:

```text
Return-state fingerprint:
54113b41ef857c59

Output:
7a56cb57bc6d988b1718f62ef637554377e6412790d1f66a57ef6cf0cf9b49c4
```

Prototype B comparator vector:

```text
Return-state fingerprint:
0a1f71372745bf1c

Output:
fd521b9f212b63d7fe68506a361062b9611076c285ff7d0dc20248f5fcf6ee2a
```

The B vector is not a Candidate C1 vector.

## Explicit non-claims

Candidate C1 does not define or claim:

- variable-length key derivation;
- proof of PRF security;
- a specific classical or post-quantum security level;
- arbitrary chosen-related-key/message security;
- general state-recovery resistance;
- side-channel, fault or constant-time security;
- production suitability.

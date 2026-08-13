# PVC-AEAD-0 Candidate A1 Independent Implementation

## Purpose

Candidate A1 includes a second AEAD wrapper written from
`docs/SPECIFICATION.md`. Its purpose is to test that the specification is
single-valued and that the canonical implementation does not contain a silent
encoding or sequencing convention.

## Independence boundary

The independent implementation is located at:

```text
independent/cpp_spec/
```

It:

- does not include `pvcaead0/aead.hpp`;
- does not link `pvc_aead0`;
- independently implements StreamFrame and AuthContext construction;
- independently implements counter iteration and XOR encryption;
- independently enforces verify-before-decrypt;
- uses Candidate M1's independent wrapper rather than its canonical wrapper;
- shares only the frozen PVC-PRF-1 Candidate C1 primitive.

The closure target is the AEAD and MAC composition layers. It is not a second
implementation of Candidate C1.

## Deliberate coding differences

The canonical implementation appends fields to dynamically sized vectors. The
independent implementation allocates exact frame sizes and writes fields at
fixed offsets. It also exposes a separate namespace and API types.

Agreement therefore tests the written field positions, byte order, tag-profile
binding, counter schedule, XOR direction, authentication input, and opening
order rather than merely exercising the same wrapper code twice.

## Interpretation

Matching outputs support interoperability and specification unambiguity. They
do not prove the pseudorandomness of C1, the unforgeability of M1, resistance to
side channels or faults, or any quantified classical or post-quantum security
level.

# Architecture

PVC-RotSymEnc-1 is an umbrella profile, not a new cryptographic layer.

## Public composition

```text
PVC-PRF-1 Candidate C1 / v0.9.0
    fixed 256-bit keyed output
                |
                v
PVC-MAC-0 Candidate M1 / v0.2.0
    injective PRF-as-MAC frame
                |
                v
PVC-AEAD-0 Candidate A1 / v0.2.0
    C1 nonce+counter stream + M1 Encrypt-then-MAC
                |
                v
PVC-RotSymEnc-1 / v0.1.0-draft
    public name, API profile, conformance and review package
```

The final arrow adds no cryptographic operation. `src/symmetric_encryption.cpp` is
intentionally a narrow adapter to Candidate A1.

## Perfect Value Cube core

The Perfect Value Cube remains the cryptographic state at the bottom of both A1
paths. It is intentionally not duplicated in the RotSymEnc wrapper.

```text
                         PVC-AEAD-0 Candidate A1
                          /                    \
                         /                      \
        confidentiality /                        \ integrity
                       v                          v
         C1_Kenc(StreamFrame)          PVC-MAC-0 Candidate M1
                                                |
                                                v
                                          C1_Kmac(Frame)
                       \                         /
                        \_______________________/
                                   |
                                   v
                         PVC-PRF-1 Candidate C1
                                   |
                                   v
                         Cube::perfect()
                                   |
                                   v
                    kPerfectCube: 8×8×8 = 512 cells
                                   |
                                   v
                    keyed X/Y/Z line rotations
                       Cube::rotate_line(...)
```

The byte-preserved implementation is located at:

```text
external/pvc_aead0_a1/
  external/pvc_mac0_m1/
    external/pvc_prf1_c1/
      include/pvc1/cube.hpp
      src/cube.cpp
      src/controller.cpp
```

`src/cube.cpp` defines `kPerfectCube`, `Cube::perfect()`, and
`Cube::rotate_line(...)`. The C1 controller calls `rotate_line(...)` while processing
its keyed move schedule. Consequently, the cube and its rotations are not merely
historical design context: they are executed for the C1 evaluations used to generate
A1 keystream blocks and, through M1, authentication tags.

The `Rot` name refers to this inherited rotational cube core. RotSymEnc adds no second
or independent cube transformation above A1.

## Layer ownership

This separation is deliberate: weaknesses discovered in C1, M1, or A1 remain
attributable to the correct layer, while API/profile problems can be fixed without
silently mutating the cryptographic candidate.

# Independent PVC-AEAD-0 wrapper implementation

This directory contains a second implementation written from
`docs/SPECIFICATION.md` for the Candidate A1 closure exercise.

Independence boundary:

- it does not include `pvcaead0/aead.hpp`;
- it does not link the canonical `pvc_aead0` library;
- it independently implements StreamFrame, AuthContext, counter iteration,
  XOR encryption, Encrypt-then-MAC sequencing, tag-size handling, and open;
- it uses the independent Candidate M1 wrapper rather than the canonical MAC
  wrapper;
- both implementations share only the frozen PVC-PRF-1 Candidate C1
  primitive, because the closure target is the AEAD composition layer rather
  than a second C1 implementation.

The implementation deliberately uses fixed-offset frame construction and a
separate API namespace.

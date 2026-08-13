# Independent PVC-MAC-0 wrapper implementation

This directory contains a second implementation written from
`docs/SPECIFICATION.md` for the Candidate M1 closure exercise.

Independence boundary:

- it does not include `pvcmac0/mac.hpp`;
- it does not link the canonical `pvc_mac0` library;
- it independently implements framing, tag-size handling, truncation, and
  verification;
- it shares only the frozen vendored PVC-PRF-1 Candidate C1 primitive, because
  the closure target is the MAC composition layer rather than a second C1
  implementation.

The implementation deliberately uses a different coding structure: an exact
pre-sized frame, fixed-offset stores, and an independent API namespace.

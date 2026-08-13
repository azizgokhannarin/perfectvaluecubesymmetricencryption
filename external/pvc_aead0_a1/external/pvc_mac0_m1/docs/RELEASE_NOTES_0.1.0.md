# PVC-MAC-0 v0.1.0 Release Notes

Initial experimental repository release.

- Added direct C1-based MAC construction.
- Added canonical binary framing with context and message lengths.
- Bound tag size to the frame.
- Restricted tags to 128, 192, and 256 bits.
- Added non-early-exit verification loop.
- Vendored frozen PVC-PRF-1 Candidate C1 v0.9.0 sources.
- Added known-answer, framing, binding, verification, and binary-input tests.
- Added vector generator, exhaustive short-frame audit, and message-bit avalanche probe.

This version is a research starting point, not a frozen candidate.

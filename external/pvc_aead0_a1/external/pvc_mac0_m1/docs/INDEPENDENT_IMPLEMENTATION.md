# Candidate M1 Independent Wrapper Implementation

## Purpose

The second implementation checks that `docs/SPECIFICATION.md` is sufficiently precise to reproduce PVC-MAC-0 framing, truncation, and verification without copying the canonical wrapper control flow.

## Independence boundary

The implementation under `independent/cpp_spec/`:

- does not include `include/pvcmac0/mac.hpp`;
- does not link the canonical `pvc_mac0` library;
- defines a separate namespace and API;
- independently encodes the fixed header, U64BE lengths, tag-size field, context, and message;
- independently truncates the 256-bit C1 output;
- independently implements supported-length checking and full-byte verification.

Both implementations deliberately share the frozen vendored PVC-PRF-1 Candidate C1 primitive. Candidate M1 closes the MAC-wrapper specification, not the separate PRF project's full independent-implementation objective.

## Deliberately different implementation structure

The canonical wrapper appends fields to a reserved vector. The independent implementation instead:

- allocates the exact final frame size,
- copies a fixed 14-byte prefix,
- stores the tag-size byte at a fixed offset,
- writes both U64BE lengths directly into fixed offsets,
- copies context and message into their calculated ranges.

This reduces the chance that both implementations reproduce the same coding mistake by following identical control flow.

## Validation

The independent implementation passed:

- all 48 retained v0.1.0 KAT vectors;
- 4,096 deterministic randomized binary differential cases;
- cross-verification in both directions;
- invalid-length and API-misuse tests.

See `DIFFERENTIAL_VERIFICATION.md` for the exact comparison surface and limitations.

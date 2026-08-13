# PVC-AEAD-0 v0.2.0 Release Notes

v0.2.0 freezes the unchanged v0.1.1 construction as **Candidate A1** after the
independent-reimplementation gate.

Added:

- independent AEAD wrapper written from the specification;
- use of Candidate M1's independent MAC wrapper in the second path;
- 48-vector independent KAT reproduction;
- 4,096-case differential corpus;
- differential checks for frames, used keystream, ciphertext, authentication
  context, tags, cross-opening, and tamper rejection;
- Candidate A1 freeze, differential, and independence documentation;
- candidate and source manifests;
- v0.2.0 reproducibility campaign.

Unchanged:

- `src/aead.cpp` construction logic;
- frame formats;
- C1 and Candidate M1 snapshots;
- canonical KAT corpus and outputs;
- key, nonce, tag, counter, and length profiles.

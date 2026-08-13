# Contributing

Cryptanalysis, independent implementations, specification ambiguity reports, and reproducibility reports are welcome.

A useful report should include:

- exact repository version,
- compiler and build flags,
- key/context/message/tag-length inputs,
- expected and observed outputs,
- minimal reproduction code or command,
- whether the result is a correctness defect, frame ambiguity, forgery, distinguisher, related-key relation, or side-channel observation.

Do not silently modify `external/pvc_prf1_c1`. A primitive change belongs in the PRF repository and requires an explicit dependency migration.

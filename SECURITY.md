# Security Policy

PVC-RotSymEnc-1 is experimental cryptographic research. Do not deploy it to protect real data.

Security reports should distinguish:

1. public wrapper/profile defects;
2. PVC-AEAD-0 Candidate A1 defects;
3. PVC-MAC-0 Candidate M1 defects;
4. PVC-PRF-1 Candidate C1 defects.

For reproducibility, include exact version, compiler, commands, complete test inputs or deterministic generators, and raw outputs.

Public, reproducible cryptanalysis and conformance results should use the
repository's **Cryptanalysis or conformance finding** issue form. A report that
should initially remain private can use GitHub private vulnerability reporting
from the repository's Security page. Do not include real keys, credentials, or
production data in either channel.

Because this repository is explicitly not for production use, no production
deployment is covered by a security-support promise or response-time service
level.

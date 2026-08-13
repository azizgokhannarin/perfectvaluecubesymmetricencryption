# PVC-AEAD-0 Candidate A1 / v0.2.0 Nonce Requirements

## Mandatory rule

A nonce must never repeat for any `seal` operation under the same encryption key. The repository adopts the stronger operational rule that nonces remain unique regardless of tag profile.

## Why reuse is catastrophic

For equal stream inputs, the same keystream is generated. Reusing a nonce under the same encryption key and tag profile gives:

```text
C1 XOR C2 = P1 XOR P2
```

for every overlapping byte. Authentication does not repair this confidentiality loss. The test `nonce-reuse-xor-demonstration` and tool `pvc-aead0-nonce-reuse-demo` reproduce the relation.

## Recommended allocation methods

- Use a persistent 192-bit monotonically increasing counter scoped to the encryption key; or
- use uniformly random 192-bit nonces from a reliable system random generator while tracking collision risk.

The library intentionally does not generate nonces because safe generation requires application-specific persistence and concurrency control.

## Random-collision estimate

For `q` uniformly random 192-bit nonces, the approximate collision probability is:

```text
q(q-1) / 2^193.
```

This is not a substitute for correct system design. Process rollback, VM snapshots, cloned devices, restored backups, and concurrent writers can cause deterministic nonce reuse even when the nominal space is large.

## Replay

Nonce uniqueness does not itself provide replay detection. Protocols must maintain sequence, epoch, session, or state rules when replay matters.

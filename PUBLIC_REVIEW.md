# PVC-RotSymEnc-1 Public Review Request

Public review snapshot: `v0.1.0-draft-review.1`

PVC-RotSymEnc-1 is experimental cryptographic research. This review request is
an invitation to falsify the construction, specification, implementation, and
recorded evidence. It is not a security endorsement, production release, or
standards proposal.

## Frozen review target

The snapshot retains the `0.1.0-draft` construction and is byte-exactly
equivalent to frozen PVC-AEAD-0 Candidate A1 / v0.2.0, including its Candidate
M1 / v0.2.0 and Candidate C1 / v0.9.0 dependencies. The public wrapper adds no
cryptographic transformation.

During this review cycle, documentation, tests, analysis tools, and
reproducibility fixes may be added without changing the frozen construction.
Any byte-semantic change to C1, M1, A1, or the public profile requires an
explicit new candidate and new canonical vectors.

## Highest-value review questions

Reviewers are especially invited to look for:

1. practical distinguishers, state recovery, key recovery, forgery, or
   confidentiality attacks against C1, M1, A1, or the composed profile;
2. rotational, cube-axis, affine, differential, equivalent-state, equivalent-
   key, short-cycle, or low-dimensional structure missed by the retained
   campaigns;
3. collisions or ambiguities in `StreamFrame`, `AuthContext`, counter, length,
   nonce, or tag-profile domains;
4. a disagreement between the normative specification, public wrapper,
   canonical vectors, and frozen Candidate A1;
5. an authentication path that releases plaintext without verifying the exact
   nonce, associated data, ciphertext, and tag profile;
6. an exploitable extension of the recorded secret-key-dependent timing or
   software-fault observations.

`CRYPTANALYSIS_CHALLENGE.md` assigns stable `RSE-C1` through `RSE-C8`
classifications to the main finding classes.

## Known findings and non-claims

Start from the known evidence rather than treating the package as a clean
security claim:

- the current C1 implementation showed repeatable secret-key-dependent timing
  on the tested x86-64 host;
- nonce reuse under one encryption key repeats keystream and reveals plaintext
  XOR relations;
- a bounded software-fault campaign found late-reachability, silent-prefix,
  and distance-one tag-prefix behavior at a registered injection boundary;
- the reference implementation is slow and is not optimized for deployment;
- no retained negative campaign proves that C1 is a PRF or that the composed
  profile satisfies a formal AEAD security definition.

The full classifications, parameters, results, interpretations, and limits are
in `docs/ATTACK_LOG.md` and the linked campaign reports.

## Fast reproduction path

```bash
git checkout v0.1.0-draft-review.1
sha256sum --check --quiet SOURCE_MANIFEST.SHA256
sha256sum --check --quiet PROFILE_MANIFEST.SHA256
./scripts/verify_candidate_a1_manifest.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DPVCROTSYMENC1_WARNINGS_AS_ERRORS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For the fail-closed GNU/Linux campaign, install the pinned CBMC version and
run:

```bash
CBMC=/path/to/cbmc ./reproduce_all.sh
```

See `AUDIT_PACKAGE.md` for the recommended reading order and
`docs/REPRODUCIBILITY.md` for exact dependencies, retained results, and
limitations.

## Reporting a result

Use the repository's **Cryptanalysis or conformance finding** issue form for a
public result. Include the exact tag or commit, deterministic inputs or a
generator, commands, compiler and flags, search budget, raw output, result,
interpretation, and limitations. Never submit real keys, private data, or
credentials.

Findings that should initially be private can use GitHub private vulnerability
reporting. `SECURITY.md` describes the reporting boundary. A negative campaign
is welcome when its tested domain and budget are explicit; it is evidence, not
a security proof.

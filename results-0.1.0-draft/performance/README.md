# Performance Campaign Records

## Attempt 1: Invalid RSS Metric

### Question

Can the pre-registered 48-case GCC/Clang performance matrix produce valid
latency, TSC, throughput, and resident-memory measurements?

### Method

Attempt 1 used benchmark/runner version 1 from commit
`ff110978bdaa11284aaccdd6c13f2301e349b64b`. Its parameters and ordering match
`docs/PERFORMANCE_CHARACTERIZATION.md`. It used
`getrusage(RUSAGE_SELF).ru_maxrss` for the resident-memory fields.

### Parameters

- GCC 14.2.0 and Clang 19.1.7 Release builds;
- Intel Core i7-10710U, Linux x86-64, CPU 0;
- 48 cases per compiler;
- five samples below 64 KiB and three samples at or above 64 KiB;
- 100 ms calibration target and fixed seed `0x50455246424D4B31`.

### Result

Both records completed 48/48 cases and passed their `seal` length and successful
`open` plaintext checks. Latency, throughput, and TSC samples were populated.
The resident-memory fields are invalid: `ru_maxrss` retained the launcher's
pre-`exec` high-water value. An otherwise identical zero-byte invocation
reported approximately 11 MiB under the Python launcher and 16 MiB under a
direct shell launcher.

### Interpretation

Attempt 1 falsified the assumption that process self-reported `ru_maxrss` begins
at the benchmark executable's `exec` boundary. The attempt is superseded as a
complete performance campaign. It is retained to preserve the measurement
failure and may be used only to audit the replacement run, not as the published
primary result.

### Limitations

The fault affects the RSS fields, not the wall-clock or TSC acquisition code.
Nevertheless, those unaffected fields are not promoted selectively because a
complete replacement run is practical. This finding says nothing about the
candidate construction's cryptographic behavior.

### Reproduction

The original records are:

```text
GCC14_ATTEMPT1_INVALID_RSS.json
CLANG19_ATTEMPT1_INVALID_RSS.json
```

The corrected benchmark/runner version 2 uses Linux current RSS sampled with
the final API output retained outside the timed interval. Reproduction commands
are in `docs/PERFORMANCE_CHARACTERIZATION.md`.

## Primary Version 2 Campaign

### Question

What latency, throughput, invariant-TSC cost, and retained-output current RSS
does the public wrapper exhibit across the pre-registered matrix?

### Method And Parameters

The version 2 primary campaign used commit
`3babb370a1bbeecea37e50db55cbf2fa8645da85`, CPU 0, GCC 14.2.0 and Clang
19.1.7, 48 cases per compiler, and the unchanged parameters in
`docs/PERFORMANCE_CHARACTERIZATION.md`.

### Result

- Both compilers completed 48/48 cases; all successful opens returned the exact
  plaintext.
- GCC reached approximately 0.066 MiB/s from 4 KiB through 1 MiB.
- Clang reached approximately 0.089 MiB/s at 64 KiB and in five of six 1 MiB
  rows.
- Excluding one non-reproduced Clang row, Clang was 1.275-1.342 times faster
  than GCC for matched cases including zero-byte calls; the median ratio was
  1.297.
- Zero-byte median latency was 0.569-0.576 ms with GCC and 0.443-0.450 ms with
  Clang.
- 1 MiB retained-output current RSS was 7,580-7,588 KiB (GCC seal),
  6,564-6,572 KiB (GCC open), 7,508-7,568 KiB (Clang seal), and
  6,488-6,552 KiB (Clang open).

The Clang 128-bit successful-open row at 1 MiB measured 0.077713 MiB/s while
the 192/256-bit rows were approximately 0.0882 MiB/s. A targeted 128/192-bit
replication measured 0.088548 and 0.088624 MiB/s, so the primary difference did
not reproduce and is not classified as a stable tag-profile effect.

### Interpretation

The reference implementation is throughput-limited and becomes approximately
linear at larger inputs. Clang materially outperformed GCC on this host. No
stable seal/open or tag-profile ordering was established. These are local
implementation measurements, not cryptographic security evidence.

### Limitations

See `docs/PERFORMANCE_CHARACTERIZATION.md`. In particular, the host used a
frequency-scaling `powersave` governor, measurements were not isolated from all
OS/SMT activity, and the memory metric is current RSS with one output retained,
not a complete transient heap profile.

### Artifacts

```text
GCC14_PRIMARY.json
CLANG19_PRIMARY.json
PRIMARY_SUMMARY.csv
CLANG19_1M_OPEN_REPLICATION.json
```

## External OpenSSL Control

OpenSSL 3.5.6 was measured separately with its `speed -aead` path, one pinned
CPU, 1 MiB buffers, and three elapsed seconds per operation:

| Control | Encrypt | Decrypt |
|---|---:|---:|
| AES-256-GCM | 4150.667 MiB/s | 4178.333 MiB/s |
| ChaCha20-Poly1305 | 2202.667 MiB/s | 2191.667 MiB/s |

The raw commands and output are in `OPENSSL_3_5_6_EXTERNAL_CONTROL.txt`.
OpenSSL is not linked into PVC-RotSymEnc-1. This is not an API-equivalent
comparison and does not alter or repair the candidate construction.

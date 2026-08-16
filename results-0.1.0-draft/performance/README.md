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

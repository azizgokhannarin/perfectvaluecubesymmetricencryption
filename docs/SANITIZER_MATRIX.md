# Sanitizer and Optimization Matrix

Date: 2026-08-16

Base revision: `74b4266550cb5ac453b69423d5b6b96fb33ca4f3`

## Question

Does the frozen PVC-RotSymEnc-1 wrapper and its complete vendored C1/M1/A1 call
tree exhibit memory-safety, undefined-behavior, uninitialized-read, or
optimization-sensitive failures under the current deterministic test corpus?

## Method

The build system was given an opt-in `PVCROTSYMENC1_SANITIZER` cache setting.
The selected compiler and linker flags are installed before the vendored A1
subdirectory is added, so the candidate dependency tree and wrapper are
instrumented together.

The following independent profiles were built with warnings as errors:

- AddressSanitizer at `-O2` with frame pointers;
- UndefinedBehaviorSanitizer at `-O2` with frame pointers;
- MemorySanitizer at `-O2`, origin tracking level 2, frame pointers, and sibling
  call optimization disabled;
- unsanitized Clang builds with explicit `-O0`, `-O2`, and `-O3`.

Each profile ran the six-test CTest suite, including canonical-vector,
round-trip, tamper rejection, tag-profile rejection, byte equivalence, and the
deterministic wrapper/A1 equivalence corpus.

The sanitizer usage follows the official Clang documentation:

- https://clang.llvm.org/docs/AddressSanitizer.html
- https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
- https://clang.llvm.org/docs/MemorySanitizer.html

## Parameters

- Platform: Linux x86-64
- Compiler: Debian Clang 19.1.7
- Standard library: system GCC 14 `libstdc++`
- C++ language level: C++20
- Sanitizer optimization: CMake `RelWithDebInfo` (`-O2 -g -DNDEBUG`)
- MSan origin tracking: `-fsanitize-memory-track-origins=2`
- Equivalence cases per CTest profile: 512
- Explicit optimization profiles: `-O0`, `-O2`, `-O3`

## Result

| Profile | CTest | Findings | Elapsed |
| --- | ---: | ---: | ---: |
| Clang ASan `-O2` | 6/6 | 0 ASan findings | 3.88 s |
| Clang UBSan `-O2` | 6/6 | 0 UBSan findings | 3.58 s |
| Clang MSan `-O2` | 6/6 | 0 candidate-path MSan findings | 10.13 s |
| Clang `-O0` | 6/6 | 0 mismatches | 23.20 s |
| Clang `-O2` | 6/6 | 0 mismatches | 2.20 s |
| Clang `-O3` | 6/6 | 0 mismatches | 2.18 s |

All explicit optimization levels preserved the tested canonical and
wrapper-to-A1 behavior.

### MSan standard-library control

The first MSan probe reported an uninitialized `memcmp` read inside
`std::ctype<char>::_M_widen_init()` after the long equivalence test completed.
Origin tracking attributed the poisoned stack bytes to destruction of a
`std::vector` in instrumented code. The same report was reproduced without any
PVC code by `analysis/msan_libstdcpp_boundary_probe.cpp`: destroy a vector, then
perform the first `std::ostream` numeric insertion.

This control isolates the report to MSan destructor poisoning crossing into the
uninstrumented system `libstdc++` output path. Replacing only the test programs'
success/failure reporting with C stdio removed that output-only boundary. The
full suite then passed with default destructor poisoning still enabled; the
candidate implementation and test predicates were not changed.

Clang's MSan documentation states that all dependent code should be instrumented
and that uninstrumented libraries can cause false reports. Therefore, the MSan
result is retained as bounded evidence, not described as full-system MSan
cleanliness.

## Interpretation

No ASan, UBSan, or candidate-path MSan finding was observed in this bounded
campaign. No optimization-dependent semantic mismatch was observed at the
three tested levels. This increases assurance about the exercised
implementation paths but does not establish memory safety for all inputs or
cryptographic security.

## Limitations

- The local ASan runner is ptrace-restricted, so local runs used
  `ASAN_OPTIONS=detect_leaks=0`. GitHub Actions retains `detect_leaks=1`.
- System libc and `libstdc++` are not fully MSan-instrumented. Runtime
  interceptors reduce but do not eliminate this limitation.
- The deterministic CTest equivalence budget is 512 cases per profile.
- Sanitizers only observe executed paths and cannot prove absence of defects.
- The matrix does not test concurrency; TSan is deferred until a parallel API
  exists.
- No construction source or canonical vector was modified by this work.

## Reproduction

AddressSanitizer (use `detect_leaks=0` only in a ptrace-restricted runner):

```bash
CC=clang CXX=clang++ cmake -S . -B build-asan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DPVCROTSYMENC1_SANITIZER=address
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  ctest --test-dir build-asan --output-on-failure
```

UndefinedBehaviorSanitizer:

```bash
CC=clang CXX=clang++ cmake -S . -B build-ubsan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DPVCROTSYMENC1_SANITIZER=undefined
cmake --build build-ubsan -j
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-ubsan --output-on-failure
```

MemorySanitizer:

```bash
CC=clang CXX=clang++ cmake -S . -B build-msan \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DPVCROTSYMENC1_SANITIZER=memory
cmake --build build-msan -j
MSAN_OPTIONS=halt_on_error=1:exit_code=86 \
  ctest --test-dir build-msan --output-on-failure
```

MSan standard-library boundary control:

```bash
clang++ -std=c++20 -O2 -g -fsanitize=memory \
  -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer \
  -fno-optimize-sibling-calls analysis/msan_libstdcpp_boundary_probe.cpp \
  -o build-msan-libstdcpp-probe
./build-msan-libstdcpp-probe
```

For the explicit optimization profiles, configure separate build directories
with an empty `CMAKE_BUILD_TYPE` and `-DCMAKE_CXX_FLAGS=-O0`, `-O2`, or `-O3`,
then build and run CTest as above.

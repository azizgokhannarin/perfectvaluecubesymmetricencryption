# PVC-MAC-0 Candidate M1 Attack and Assurance Matrix

| Class | Defense or evidence | Status |
|---|---|---|
| Context/message concatenation alias | Two fixed-width U64BE lengths; structural proof | Closed at encoding layer |
| Embedded-NUL truncation | Binary spans and explicit lengths | Regression tested |
| Prefix/suffix/extension framing alias | Lengths precede variable fields | Closed at encoding layer; bounded tests clean |
| Cross-tag-length reuse | Tag length included in frame | Regression tested |
| 256-profile prefix accepted as shorter profile | Profile-specific recomputation | Explicit rejection tests |
| Wrong-tag acceptance | Full supplied-byte XOR/OR comparison | Regression tested |
| Unsupported tag length | Public-length rejection before C1 | Invalid-length matrix tested |
| Wrong key/context/message | Recomputed profile-specific tag | Bounded integration audit clean |
| Single-byte tag modifications | Every position across 16/24/32-byte profiles | Rejected in bounded audit |
| Specification ambiguity | Independent wrapper from written spec | 48 KAT + 4,096 differential cases matched |
| Wrapper implementation divergence | Frame/full-output/tag/verify comparison | 0 mismatches |
| Frame collision in bounded short domain | 789,507-frame audit | 0 collisions; supplementary to proof |
| Message-bit diffusion | 256 one-bit flips, 256-bit tag | Baseline recorded |
| Conditional EUF-CMA rationale | PRF-as-MAC reduction | Documented; depends on C1 PRF security |
| Structured framed-input PRF behavior | Explicit assumption | No dedicated cryptanalytic campaign |
| Generic truncated-tag online forgery | `q_v / 2^t` ideal term | Theoretical term documented |
| Chosen-message structural forgery | Inherited principally from C1 | Open to external cryptanalysis |
| Related-key MAC forgery | No special reduction claim | Open |
| Full nonlinear state recovery | Inherited open C1 problem | Open |
| Complete constant-time behavior | C1 has data-dependent memory access | Not claimed |
| Fault attacks | No countermeasure | Out of scope |

# PVC-AEAD-0 Candidate A1 Assurance Matrix

| Surface | Check / argument | Result / status |
|---|---|---|
| Empty plaintext | seal/open plus authenticated AD | Passed |
| Binary data | embedded `00` and `ff` | Passed |
| Multi-block encryption | boundary and randomized plaintext lengths | Passed |
| Nonce binding | changed nonce | Ciphertext/tag changed; open rejected |
| Associated-data binding | changed AD | Ciphertext unchanged; tag/open changed |
| Ciphertext integrity | changed ciphertext | Rejected |
| Tag integrity | changed tag | Rejected |
| Encryption-key binding | changed `K_enc` | Ciphertext changed |
| Authentication-key binding | changed `K_mac` | Tag changed; old tag rejected |
| Key-role profile | independent canonical KAT | Passed; equal/related keys remain out of model |
| Tag-profile separation | 128/192/256 | Ciphertexts and tags separated |
| Cross-profile prefix | 256-bit tag prefix as shorter tag | Rejected |
| Invalid tag length | bounded length matrix | Rejected |
| Verify-before-decrypt | invalid tag | No plaintext returned |
| Stream injectivity | fixed-field proof plus boundary tests | Established structurally / tests passed |
| Auth-context injectivity | fixed fields plus `U64BE(len(AD))` proof | Established structurally / tests passed |
| Frame-family separation | role bytes `53` and `41` | Established structurally / test passed |
| Counter byte order | seven 64-bit boundary values | Canonical and independent wrappers matched |
| Counter wrap | payload bound implies at most `2^59` blocks | Unreachable for admissible input |
| Nonce reuse | two equal-length messages | XOR relation reproduced; unsafe by design |
| KAT corpus | 48 binary vectors, two AEAD wrappers | 48/48 in both implementations |
| Wide differential | 4,096 binary tuples | All compared fields and cross-open results matched |
| Differential tag tamper | 512 tuples, both wrappers | 0 unexpected acceptances |
| Differential nonce tamper | 64 tuples, both wrappers | 0 unexpected acceptances |
| Differential AD tamper | 64 tuples, both wrappers | 0 unexpected acceptances |
| Differential ciphertext tamper | 63 non-empty tuples, both wrappers | 0 unexpected acceptances |
| Framing regression | 30,720 stream/auth frames | 0 collisions |
| Composition regression | 128 tuples / 510 modifications | 0 unexpected acceptances |
| Dependency preservation | Candidate M1 and nested C1 manifests | Verified unchanged |

This table is an implementation, interoperability, and composition record. It is not a cryptanalytic proof. Dedicated AEAD input-subdomain analysis, simultaneous two-key attacks, nonce-allocation failures, side channels, faults, and large-scale forgery analysis remain external-review topics.

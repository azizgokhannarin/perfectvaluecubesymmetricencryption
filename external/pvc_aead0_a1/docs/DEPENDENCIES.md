# Frozen Dependencies

PVC-AEAD-0 Candidate A1 / v0.2.0 vendors the complete **PVC-MAC-0 Candidate M1 / v0.2.0** repository under:

```text
external/pvc_mac0_m1/
```

That snapshot contains its own pinned **PVC-PRF-1 Candidate C1 / v0.9.0** dependency. Runtime code compiles M1's canonical `src/mac.cpp` and the nested C1 source files without patching them.

`DEPENDENCY_MANIFEST.SHA256` records every vendored file. AEAD-specific changes must never be made inside the dependency tree. Any dependency change requires a separately versioned AEAD profile and renewed interoperability review.

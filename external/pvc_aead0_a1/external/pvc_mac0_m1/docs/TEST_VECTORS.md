# PVC-MAC-0 Candidate M1 Test and Differential Vectors

## Retained known-answer corpus

The original 48-vector corpus remains byte-for-byte unchanged:

```text
vectors/PVC_MAC0_VECTORS_0.1.0.csv
vectors: 48
SHA-256: 482b36274d940c1279a69b47c9254bbcfb1fb1c821c2dfacce39441fb9cca1ea
```

Both canonical and independent wrappers reproduce all 48 vectors.

CSV columns:

```text
index,key_hex,context_hex,message_hex,tag_bytes,tag_hex
```

## Candidate M1 wide differential corpus

```text
vectors/PVC_MAC0_DIFFERENTIAL_M1.csv
vectors: 4096
SHA-256: 941fddaf40f82bcf7929d7be1a9f396676bd75b1e7496e9c2594e6aa408078d6
```

CSV columns:

```text
index,key_hex,context_hex,message_hex,tag_bytes,frame_hex,full_output_hex,tag_hex
```

The corpus covers all supported tag sizes, binary values, empty fields, and explicit size boundaries. See `DIFFERENTIAL_VERIFICATION.md`.

## Primary known-answer vectors

```text
K = 00 * 32, C = empty, M = empty, t = 32
Tag = 1c3f146197db72c01793c5a80d2c6586ab544053e82d1fffae50f339c92421d4

K = 00 * 32, C = empty, M = ASCII "abc", t = 32
Tag = 1d6ea3a692d0dbf839adb1d4c3e31b2d1a4e0887351d14d1834b3ab88c4cc35f

K = 000102...1f
C = 50564300
M = 00017f80ff
t = 16
Tag = e36f8f6a274aab512b5245e61f1bced8
```

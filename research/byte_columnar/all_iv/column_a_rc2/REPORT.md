# RC2 column-A synthetic control report

**Identity:** ASTRA

## Outcome

All source-backed RC2 controls passed. No Rev7 target was read or evaluated.

The unchanged historical C primitive reproduced its embedded KAT and matched independent PyCryptodome ARC2 with `effective_keylen=1024` for 32 blocks at each of four key lengths: 5, raw 7-byte `Zombies`, 16, and 128 bytes. The fixed native wrapper matched all 32 raw-key block vectors. Complete 256-byte CFB8 streams under two IVs matched the source-backed Python recurrence, PyCryptodome `MODE_CFB` with `segment_size=8`, and the native implementation; both native decryptions roundtripped exactly.

Two complete width-9 planted scans matched the Python column-A reference on every ordered prefix/candidate set and all counters. Both contain rejection and survival and retain the true first-eight tuple and ninth rank:

| IV | Examined | Rejected | Survivor prefixes | Native seconds |
|---|---:|---:|---:|---:|
| `3030303030303030` | 362,880 | 358,726 | 4,154 | 0.0556489 |
| `0011223344556677` | 362,880 | 358,601 | 4,279 | 0.0551608 |

Short two-row cases compare the first 1,000 prefixes at wider widths and deliberately exercise masks with more than one candidate:

| Width | Rejected | Survivors | Multiple-candidate survivors | Unexamined |
|---|---:|---:|---:|---:|
| 10 | 693 | 307 | 29 | 1,813,400 |
| 13 | 416 | 584 | 187 | 51,890,840 |
| 14 | 359 | 641 | 261 | 121,079,960 |

Exact ordered sets, FNV-1a digests, block calls, row counts, candidate tests, and rejected/unresolved/unexamined factorial weights agree. Seven malformed inputs are rejected.

## Bounded benchmark

A 546-byte public synthetic fixture from `random.Random(0xC01A2C2)` was scanned for the first one million lexicographic prefixes in count-only mode. The ledger retains the full native JSON:

| Width | Rows | Block calls | Candidate tests | Seconds | Prefixes/s | Linear full-prefix projection |
|---|---:|---:|---:|---:|---:|---:|
| 13 | 42 | 3,080,398 | 8,480,330 | 0.304018 | 3,289,279 | 15.78 s |
| 14 | 39 | 3,178,823 | 10,169,572 | 0.321994 | 3,105,648 | 38.99 s |

The exact prospective eight-cell workload would be 691,891,200 prefixes. Four times these synthetic per-width projections totals about 219 seconds. This is a host/fixture estimate only; target-specific early stopping changes block-call counts.

## Provenance and hashes

- `native.cpp`: `3c634ea5fa32caa146c2a078f85abdbc98984675744e7ffcf1977355e455a1cd`
- `controls.py`: `c9c32b8a3e95699e42c6edd961928b85a51098a42e966639d85826b4650d4006`
- `controls.json`: `7330bad3670745ef659dd597a3385ee06b7225b17eadb997a0e80519ac3abb9f`
- unchanged `source/rc2.c`: `37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19`
- empty `source/rc2.h`: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `source/COPYING.LIB`: `ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532`
- minimal `source_build/libdefs.h`: `556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e`
- accepted column-A `core.py`: `1deda1788e9d9a49140325c7e0f7ce3eb53aa7d05e8e44590be4076da0bae472`
- accepted column-A proof ledger: `2fb68eff8b80fb120ca972a29ead64268f03057c10c00156fd49152e0cf62bea`

The tested tools were Python 3.9.6, PyCryptodome 3.23.0, and Apple Clang 21.0.0. The historical source emits two pointer-sign warnings in its embedded self-test code; compilation and every asserted control succeed.

## Limits

This is a synthetic implementation and feasibility result only. No target driver, gate, or target result exists in this package. A future target would still require separate review, exact preregistration, retained survivors, and independent candidate-mask replay.

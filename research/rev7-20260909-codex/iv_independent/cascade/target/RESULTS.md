# Cascade target results (ASTRA)

The single preregistered target run completed successfully in execution session `57359`. It used the immutable publication commit `0d5b29becd8b780bba6074d78b65355b4caf07a9`, gate SHA-256 `80471b6c6de67bfa07370a5b18c0a024200f6a6b7b5617df79bc5562d9605620`, and frozen driver SHA-256 `dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41`. The process exited zero and was not restarted.

## Result

All 22,764 unique registered path endpoints were rejected by the A105 necessary byte predicate:

| Depth | Endpoints | A105 rejected | Retained | Empty/inconclusive |
|---:|---:|---:|---:|---:|
| 1 | 28 | 28 | 0 | 0 |
| 2 | 784 | 784 | 0 | 0 |
| 3 | 21,952 | 21,952 | 0 | 0 |
| **Total** | **22,764** | **22,764** | **0** | **0** |

There were no strict-FSA transition or terminal rejections because every case had already failed A105. There were no candidates requiring the driver's two-IV retained-candidate replay. Rejected intermediate endpoints still expanded through the registered maximum depth; the exact depth counts certify that no intermediate endpoint pruned its descendants.

The full result is 23,151,009 bytes with SHA-256 `2eb167a4ec5503a3b27fe84dd4a3a96f781443eade8d78bfefdab9ff01aacf7e`. The driver did not persist elapsed timing, so this report does not infer a benchmark from filesystem timestamps or tool polling latency.

## Finite scope

The run covers seven fixed-key CFB8 backends (AES-128, DES, standard Blowfish, historical Blowfish compatibility, RC2 with effective key length 1024, Twofish, and Loki97), direct binary depths one through three, four outer byte orientations, and four involutions at every interlayer boundary. Every external layer IV is covered by the proven CFB8 known-interval recurrence; IV bytes are neither guessed nor recovered.

The endpoint allows TAB/LF/CR, ASCII 32–126, and the five registered UTF-8 punctuation sequences. This result does not cover other keys, modes, encodings, transpositions, framing, padding changes, truncation, other transforms, deeper cascades, or other Unicode. It does not recover bytes outside each derived interval.

## Lossless package and verification

`target_results.pack.json` is a deterministic zlib level-9/RFC-1924-base85 envelope of the exact original JSON bytes. It is 1,562,439 bytes; the compressed payload is 1,249,674 bytes. Its SHA-256 is `31b57482ed2898a901509cd4d9eb4c5da2da3aa9918ebac3aee7150a4dcd1da7`.

Portable verification uses only the Python standard library:

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/pack_results.py
```

The verifier safely bounds decompression to the declared 23,151,009 bytes, reconstructs the exact original result SHA, verifies the gate and every pinned source artifact, enumerates the complete Cartesian ID set, recomputes every interval geometry, checks all summaries, and validates all 22,764 stored A105 witnesses structurally. This is not a second target cryptographic evaluation.

To reconstruct the byte-identical full ledger at a new path:

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/pack_results.py \
  --unpack /tmp/cascade-target-results.json
```

The unpack command refuses an existing destination. The original full result remains preserved locally.

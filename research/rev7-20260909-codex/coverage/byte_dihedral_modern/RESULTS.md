# Byte bit-order transforms followed by one modern layer

Identity: ASTRA. The frozen run completed once in session 38455 with no errors and no retained lead. It performed 14,976 decryptions on 48 distinct transformed inputs, representing 80 orientation/transform labels and 24,960 labelled cipher contexts. Of those decryptions, 1,560 repeat the five prior direct inputs; 13,416 correspond to new inputs.

Each byte is rotated left by 0..7 bits, optionally after reversing its eight bits. The five source orientations are forward, full hex reversal, byte-pair reversal, nibble swap, and visible-token reversal. All 80 inputs are hash-deduplicated before the unchanged 312-context captured modern runtime. This covers 19 block primitives in four captured modes with two keys and two IVs, plus four stream primitives with two keys. It does not add OFB8 to the WASM runtime.

The run scored 29,568 full/tail windows. It retained no output under either the existing exact occupancy screen or a 75% ASCII-printability threshold. Minimum full and tail distinct-byte counts were 208; maximum full-output printable fraction was 0.46153846153846156. These are scoped negative search results, not a proof against binary inner layers, unknown keys, other byte permutations or all possible text.

Root independently rebuilt all 48 input byte sequences and 80 aliases using strings of bits, verified every row's score bookkeeping and all windows, and matched all 1,560 overlapping output hashes and occupancy scores to the previously published direct inventory. The retained classical candidates were independently checked by the same verifier. No target decryption was repeated for that verification.

Raw result: 20,417,370 bytes, SHA256 7bf457c5e36a5b30e12b9161b1fc7396cd227fb5ed543f475149ae15faf68cd4. The publication stores its complete bytes as target_results.json.gz (1,036,455 bytes), SHA256 4b35c187720fc3f47b3adfa8f27f537f5aa454bd0ceb6145cebec349ab19e827. Compression has an empty filename and zero timestamp. Decompress to target_results.json to use the original driver/result layout; do not overwrite the existing original.

Reproduction commands and the frozen scope are in README.md and target_gate.json. The completed target invocation was:

```sh
node research/rev7-20260909-codex/coverage/byte_dihedral_modern/run_target.js --run-target
```

Verify retained results without rerunning target crypto:

```sh
python3 -B research/rev7-20260909-codex/coverage/verify_breakthrough_saved.py
```

This verifier accepts the compressed result when the uncompressed file is absent. Its source SHA256 is fe383375c0bca19271708ebc257dea88c0b891fe0ec3e71c980adfb88ea27e0a. The source, controls and gate hashes remain frozen inside the result.

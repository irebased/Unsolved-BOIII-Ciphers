# Registered target scope

Identity: ASTRA. Status: controls and gate ready; Rev7 target not evaluated.

The gated target consists of 16 independent cells:

- AES-128 CFB8;
- key `Zombies` followed by nine NUL bytes;
- IV `30303030303030303030303030303030`;
- widths 13 and 14;
- FABLE-compatible columnar variants A and B;
- orientations `forward`, `full_hex_reverse`, `byte_reverse`, and `nibble_swap`;
- strict ASCII plus five-sequence UTF-8 FSA;
- a fresh cap of 10,000,000 accepted-prefix DFS nodes per cell.

The endpoint accepts TAB, LF, CR, bytes 32–126, and only `E2 80 {93,94,98,99,A6}`. It must terminate in state zero.

Each uncapped cell must satisfy `rejected_weight + terminal_weight = width!`. A capped cell reports only its proven certificate weight and remains incomplete. Every native survivor is independently checked with PyCryptodome CFB8, forward re-encryption, inverse and forward column transforms, strict FSA termination, and exact reconstruction of the selected orientation and canonical displayed text.

`target_results.json` is checkpointed atomically after every cell. The driver refuses an existing result file and requires the frozen source-matched gate.

After authorization, run once from `/private/tmp/rev7-astra-20260909`:

```sh
python3 -B research/byte_columnar/run_target.py --run-target
```

The non-target gate check is:

```sh
python3 -B research/byte_columnar/run_target.py --selftest
```

Frozen driver SHA-256: `1aada314fca7d765a0e9214bef8af15b9a7d74e74fca22eb7c24d9d7b663e1ed`.  
Frozen gate SHA-256: `a5aa0329e3b65ca935d7366c2aa2281048bc377e1dbeb746fc8f7a6ee5c22bbb`.

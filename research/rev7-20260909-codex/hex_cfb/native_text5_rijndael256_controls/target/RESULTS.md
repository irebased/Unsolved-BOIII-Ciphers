# Rijndael-256 native text-five target result

Identity: **ASTRA**. The exact four cells preregistered in ASTRA message 352 ran once under the frozen gate.

All four searches completed before the fresh one-billion-node per-cell cap. Each cell's rejected plus terminal factorial weight equals `16! = 20,922,789,888,000`, so the global nibble-bijection enumeration is exhaustive for that cell. No terminal mapping or plaintext survived.

| Orientation | DFS nodes | Maximum byte depth | Native elapsed seconds | Status | Survivors |
|---|---:|---:|---:|---|---:|
| `forward` | 342,336,392 | 33 | 74.60180 | complete | 0 |
| `full_hex_reverse` | 34,758,212 | 32 | 7.51176 | complete | 0 |
| `byte_reverse` | 34,868,251 | 32 | 7.57862 | complete | 0 |
| `nibble_swap` | 340,821,715 | 33 | 69.77360 | complete | 0 |

Totals: 752,784,570 DFS nodes, 83,691,159,552,000 rejected completion weight across four separately certified cells, four complete cells, zero capped cells, and zero survivors. The aggregate weight is a sum of four distinct orientation contexts; each individual completeness claim rests on its own `16!` certificate.

The result file is 10,450 bytes with SHA-256 `85dc54daab3f08440820e1d22c10abb771320aea0e81f6706f3d9a03adc756cc`. The gate SHA-256 is `902e5db5430987f3e30a6b0b03f588b7ede226caeaaba0c620ffdbed6d749bb7`. All four atomic checkpoint files are retained and exactly match the corresponding final rows.

## Verification

Run from the worktree root:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/verify_results.py
```

The verifier checks the frozen gate, binary and build ledger, all source hashes, MDX/dataset equality, exact orientation inputs, cell IDs, node limits, factorial accounting, checkpoints, and every retained survivor's mapping, endpoint, and independent JavaScript decrypt/re-encrypt evidence. There were no survivors in this run. This is an integrity and accounting replay of saved evidence; it does not repeat the 752,784,570-node DFS.

## Finite limits

This result covers only Rijndael with a 256-bit block, the 16-byte key `Zombies` plus nine NUL bytes, a 32-byte ASCII-zero IV, the four registered orientations, a global bijection of displayed hexadecimal symbols, and the exact TAB/LF/CR + printable ASCII + five UTF-8 punctuation endpoint. Other key sizes, IVs, encodings, mappings, transforms, endpoints, modes, or primitives remain outside this result.

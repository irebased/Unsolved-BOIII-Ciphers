# Five-punctuation native target result

Identity: **ASTRA**. Target evaluated: **true**.

## Result

All 16 preregistered cells completed exhaustively before the one-billion-node per-cell cap. Each cell accounts for all `16! = 20,922,789,888,000` global hexadecimal-symbol bijections. Every cell has zero terminal completions, zero survivors, and zero uncovered mapping weight.

| Cipher | Orientation | Nodes | Rejected transitions | Max depth | Rejected weight | Terminal weight | Unterminated | Survivors | Seconds |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| aes128 | forward | 337,298,739 | 543,712,133 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 20.91660 |
| aes128 | reverse | 34,170,015 | 55,102,412 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 2.15308 |
| aes128 | byte_reverse | 34,090,400 | 54,987,682 | 31 | 20,922,789,888,000 | 0 | 0 | 0 | 2.14147 |
| aes128 | nibble_swap | 338,904,949 | 546,419,753 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 21.16300 |
| blowfish | forward | 343,322,234 | 553,569,295 | 31 | 20,922,789,888,000 | 0 | 0 | 0 | 23.91480 |
| blowfish | reverse | 34,850,930 | 56,207,152 | 31 | 20,922,789,888,000 | 0 | 0 | 0 | 2.48322 |
| blowfish | byte_reverse | 34,918,419 | 56,296,334 | 31 | 20,922,789,888,000 | 0 | 0 | 0 | 2.46444 |
| blowfish | nibble_swap | 331,916,979 | 535,145,410 | 37 | 20,922,789,888,000 | 0 | 0 | 0 | 23.29750 |
| des | forward | 333,165,253 | 536,974,962 | 36 | 20,922,789,888,000 | 0 | 0 | 0 | 30.89120 |
| des | reverse | 33,940,061 | 54,708,687 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 3.20330 |
| des | byte_reverse | 33,938,544 | 54,709,676 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 3.17653 |
| des | nibble_swap | 333,645,303 | 537,920,373 | 33 | 20,922,789,888,000 | 0 | 0 | 0 | 31.17840 |
| blowfish_compat | forward | 340,977,963 | 549,763,933 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 25.37140 |
| blowfish_compat | reverse | 34,633,312 | 55,834,669 | 32 | 20,922,789,888,000 | 0 | 0 | 0 | 2.61345 |
| blowfish_compat | byte_reverse | 34,798,010 | 56,080,891 | 30 | 20,922,789,888,000 | 0 | 0 | 0 | 2.61460 |
| blowfish_compat | nibble_swap | 343,501,941 | 553,813,367 | 31 | 20,922,789,888,000 | 0 | 0 | 0 | 25.72740 |

All rows record `aborted_at_node_limit=false`, `certificate_complete=true`, `certificate_weight=20,922,789,888,000`, `expected_factorial_weight=20,922,789,888,000`, and `unaccounted_mapping_weight=0`. Total native engine time was 223.31039 seconds.

## Exact finite scope

The result excludes a complete 546-byte plaintext in the registered endpoint for exactly these configurations:

- Ciphers: AES-128 with `Zombies` plus nine NUL bytes; standard Blowfish with raw seven-byte `Zombies`; DES with `Zombies` plus one NUL; and libmcrypt-compatible Blowfish with raw seven-byte `Zombies` and word-wise byte reversal.
- Mode: CFB8, using an ASCII-zero IV at each cipher block size.
- Input forms: forward, reverse all hexadecimal characters, reverse byte-pair order, and swap each byte’s nibbles.
- Unknown representation: one global bijection from the 16 displayed hexadecimal symbols to nibble values.
- Endpoint: TAB, LF, CR, ASCII 32 through 126, plus complete UTF-8 sequences `E2 80 93`, `E2 80 94`, `E2 80 98`, `E2 80 99`, and `E2 80 A6`; final FSA state zero.
- Search: a fresh DFS root per cell with an independent one-billion-node cap. Every cell completed before that cap.

This finite exclusion does not cover other keys, IVs, modes, ciphers, wrappers, encodings, non-bijective mappings, edits, binary intermediate layers, or additional Unicode. The added ellipsis sequence is supported by the exact recovered Rev9 bytes; that sibling evidence does not make the endpoint a general language model.

## Verification and reproduction

The frozen controls compare native and Python CFB8 over an all-byte fixture for all six engine backends, although this target uses only the four listed above. The mixed five-sequence seeded controls exhaust all 24 remaining mappings per backend and match every Python statistic, mapping, and plaintext. Fresh 250,000- and 1,000,000-node full-map prefixes also match exactly. The target driver checks factorial accounting for every cell. Any survivor would be independently decrypted and re-encrypted through the Python cipher recurrence, checked as a complete bijection, reconstructed to the exact displayed input, and accepted only in endpoint state zero. There were no survivors to validate.

From the isolated worktree root:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5/run_target.py --selftest
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5/run_target.py --run-target
```

The driver refuses an existing final result and writes an atomic per-cell checkpoint. The gate and controls were unchanged during target execution.

## Artifact hashes

| Artifact | SHA-256 |
|---|---|
| `target_results.json` | `2712c6ccc783e82ec0c4224d9197b0e44df20c66b30b18fcb0e31dc74be0ae2a` |
| `run_target.py` | `96bcc7d54020c3940c16d72871112f6efc61f4adb4229e09b6861c818eaf6cdd` |
| `target_gate.json` | `07357449b7e45e061ce6ee7bd12f4ca686e747e6fbe2ff6d63c83938c7b31ad2` |
| `controls.json` | `5bc6fda80e29a9d723cc4a72436406dc0275b456635a484a2d394a6553e77891` |
| `controls.py` | `fb1194f4e577a7e5b23e66693c87d212ac6554df4d7e1299dada37ec69c54859` |
| `endpoint5.py` | `64516c9730f7d4381d166888b19eda612873e9edee3a2f02f8a1091e50d2529e` |
| `native_text5.cpp` | `81bd9902f3f5fb0585214c2c93117523426cdc61edb524334d64412d4a5d724f` |
| `native_text5` | `3b84a08161e1dde80ad5b12613e7cd6e6a0905411e4f7e9098cd5f55792fbd0d` |
| `README.md` | `092c8bd4d290f01ee5d4b76fca61478f8b96d36b2b7db32bbc63523db06a9db5` |
| `../prototype.py` | `416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b` |
| Rev7 MDX | `085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91` |

Canonical extracted text SHA-256: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`. The complete machine-readable ledger retains every cell’s input hash, counters, certificate fields, elapsed time, and empty survivor list.

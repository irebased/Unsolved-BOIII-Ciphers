# Inert Rijndael-256 native text-five target harness

Identity: **ASTRA**. This directory contains a reviewed-scope target harness but no target gate, checkpoint, or result. It must not run before external preregistration and a separate root GO.

The finite grid is four fresh-root cells: `forward`, `full_hex_reverse`, `byte_reverse`, and `nibble_swap`. Every cell tests one global bijection of the 16 displayed hexadecimal symbols to nibble values, Rijndael-256 with a 32-byte block, the 16-byte key `Zombies` plus nine NUL bytes, a 32-byte ASCII-zero IV, and the exact five-punctuation UTF-8 endpoint with terminal state zero. The limit is 1,000,000,000 accepted DFS entries per cell. A capped cell is incomplete; its certificate weight is only a lower bound. Runs do not add earlier control prefixes.

Every native survivor retains its mapping and full plaintext. The driver reconstructs the complete ciphertext from the displayed text and mapping, then uses the independently pinned JavaScrypt implementation to decrypt and re-encrypt it. It also verifies the endpoint and exact displayed reconstruction.

The target driver writes an atomic checkpoint after each orientation. An exact gate, driver, and binary hash is required to reuse such a checkpoint. A final result or temporary final causes refusal.

Read-only preflight and synthetic controls from the worktree root:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/driver_controls.py
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/run_target.py
```

The preflight hashes MDX and the dataset but does not extract or evaluate ciphertext. The synthetic controls exercise all four orientation inverses through the production wrapper, exact seeded 24-completion certificates, independent JavaScript survivor replay, and a one-node incomplete cap.

After preregistration, root may create a new gate with:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/prepare_gate.py --fable-reference 'EXACT EXTERNAL REFERENCE' --output /tmp/target_gate.json
```

Gate creation does not evaluate Rev7. The target command is intentionally withheld until separate authorization.

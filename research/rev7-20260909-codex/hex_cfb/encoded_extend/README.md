# ASTRA Base64 endpoint extension

```json
{"identity":"ASTRA","status":"completed bounded target; no survivors observed","scope":"Base64 endpoint, AES-128/Blowfish/DES, four direct orientations; 3,000,000 DFS entries per cell"}
```

This extension covers 12 cells. Six cells (reverse and byte-reverse for all three ciphers) completed exhaustively with zero survivors. Six cells (forward and nibble-swap for all three ciphers) reached the 3,000,000-node cap with zero observed survivors; they remain incomplete and cannot support a factorial exclusion. The exact frozen result is `target_results.json` (SHA-256 `6db92f9b1f1ddebf34105ec78ec4dd4935661b27fb8d3ef73c870d6447f61cc2`).

The endpoint allows the 69-byte Base64/whitespace alphabet. Input is the verified 1,092-symbol Rev7 transcription (SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`). The global mapping space is 16! per cell. The six complete cells have rejected completion weight plus terminal weight equal to 16!; capped cells have nonzero unaccounted mapping weight. No plaintext or layer was recovered.

Controls are retained in `controls.json` (SHA-256 `6ffd31702df7ae9259b4b23e146186f4247607bce8f4f31da6fbeb03e98b73e2`). The full unseeded AES/Base64 control also caps at 3M; the explicitly labelled 12-seeded/4-unknown fallback completes and recovers the planted mapping. This is a control caveat, not target evidence.

The 1M-node prefix from the prior run is repeated by fresh root traversals and is not added to these results. Source hashes recorded in the result are prototype `416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b`, prior driver `b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c`, and extension driver `255b37a642cc01feec0f4327c809a3be6917ff6cb9a33f50f5eec51bfa397aef`.

Commands (Python 3.9+, PyCryptodome):

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/encoded_extend/run_extend.py --controls
python3 -B research/rev7-20260909-codex/hex_cfb/encoded_extend/run_extend.py --run-target
```

The target command refuses existing output and checkpoint files unless explicitly resumed. Cells are checkpointed atomically.

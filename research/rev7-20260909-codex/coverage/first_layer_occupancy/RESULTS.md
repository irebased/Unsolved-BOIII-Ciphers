# Direct first-layer WASM occupancy result

```json
{"identity":"ASTRA","status":"complete","target_evaluated":true,"screen_result":"finite detector negative"}
```

The single preregistered target command completed successfully with no errors. It evaluated five exact input orientations against 19 block ciphers in four wrapper modes, two literal keys and two IVs, plus four stream ciphers with the two literal keys. This is exactly 1,560 decryptions: 1,520 block contexts and 40 stream contexts.

All 1,560 wrapper calls returned exactly 546 bytes. Block outputs were scored both in full and after skipping one native block; streams were scored in full only. The resulting 3,080 windows contained zero occupancy flags. This is a finite detector negative for this exact first-layer grid.

The minimum complete-buffer distinct-byte count was 211. The frozen threshold at length 546 is 188. Two contexts tied at that minimum:

- `byte_pair_reverse|blowfish|ncfb|ZOMBIES|ascii0`
- `visible_token_reverse|3-way|ctr|ZOMBIES|ascii0`

The minimum block-skipped-tail count was 208 for `visible_token_reverse|3-way|ctr|ZOMBIES|ascii0`. That tail has length 534 and threshold 186. Complete-buffer counts ranged from 211 through 240; tail counts ranged from 208 through 239. No output bytes needed flagged-output retention because no window was flagged.

The WASM runtime recorded exactly 1,560 calls and 1,560 complete 256-byte key-buffer clears. It recorded 1,520 IV-buffer clears, one for every block context. There were no dropped, cropped, padded, or errored outputs.

## Reproduction

The executed command was:

```sh
node research/rev7-20260909-codex/coverage/first_layer_occupancy/run_target.js --run-target
```

The result ledger is 1,149,890 bytes with SHA-256:

```
313899571bc5e9ca5152b245d6e94238891d8bcdf6081569a55fff80b0ad2d3c
```

Frozen implementation hashes:

- `runtime.js`: `fd9d62dd20105757ec41c9affca23375b7276e4bda306feed05eeb0782fd3e30`
- `model.js`: `412a1ed6c42cc8fa1ac625d5f19848e39fff1fb9967ff2587d59250776d29425`
- `controls.js`: `b38fe2cbdad6421726e463a3cd5231b18baa1b28ab704bb7898be2c838b5208b`
- `controls.json`: `185d1b1d15ca4b04d03cf0bc2d576f2d45875bdf7ff005ef57e9ded8d26e0178`
- `run_target.js`: `685d93daaa774753f5a79909084022dec5fa6e737c70215e1483f3c3289160eb`
- pinned WASM: `60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7`
- pinned generated wrapper: `8998b6dd50ebc24aede3df84228826951f2143fde393e15f95d1455e074d5061`
- pinned cipher registry/helper: `ffba90a95de78bdeef64c8d2b5602c61d3271e7780914d8322cc5bb9b912ec1d`
- occupancy scorer: `6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27`
- threshold table: `2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447`

## Limits

This result covers only the registered direct first-layer wrapper conventions, fixed keys, IVs, modes and orientations. The occupancy screen is a necessary inspection heuristic under its independent-uniform-byte calibration. An unflagged output does not exclude meaningful plaintext, a different encoding, another key or IV, another mode convention, or a multilayer construction. The block-skipped view is not an all-IV proof.

# TEA controls (superseded target proposal)

Identity: ASTRA. This package contains a small target-free control for original TEA, the closest primitive relative of the solved Rev12 XTEA layer. It does not read or decrypt Rev7. A later retained FABLE record (message 455 in `comms/inbox.jsonl`) reports that TEA was already included in a completed 1,440,168-decryption non-libmcrypt sweep with the same KAT. The proposed direct target is therefore superseded and must not run as new coverage.

The earlier bounded history snapshot found no named TEA target experiment, but that snapshot predates FABLE message 455. FABLE's captured 23-cipher registry in `dictkey2/lib.js` includes XTEA but not TEA. The frozen Revelations corpus records Rev12 as XTEA/CFB with `Zombies` and ASCII-zero IV. Those facts motivate TEA; they do not claim the author used it.

`model.py` implements the Wheeler/Needham 32-cycle TEA equations with explicit 32-bit wrapping and both big- and little-endian word packing. The big-endian all-zero key/plaintext known-answer result is `41ea3a0a94baa940`. Controls compare 512 deterministic random blocks against a separately written equation, round-trip every block, and exercise 32 full-message combinations: two padded Zombies spellings, two IVs, two word packings, and CFB8/full-block CFB/full-block OFB/CTR. All 32 recover the exact 546-byte synthetic input.

The proposed target is 2 packings × 2 keys × 2 IVs × 4 modes × 5 explicitly defined orientations = 160 retained outputs. Every output should retain exact bytes, SHA-256, 256-bin histogram/distinct count, encoded-text endpoint flags, and full plaintext candidates. The fifth orientation remains deliberately undefined here pending scope review; no target driver should freeze until all five index maps are named exactly. A positive target harness should encrypt a known 546-byte mixed UTF-8 plant through every cell and recover it exactly.

Limits: the second Python equation checks implementation parity, not an independently sourced primitive. Before a target run, pin a primary TEA source and its known-answer vector, or add a distinct implementation. This is a narrow fixed-key family, not coverage of arbitrary TEA keys, round counts, endian conventions, padding, or envelopes.

Pinned evidence read for this assessment:

```json
{
  "/private/tmp/ra-prefix-fix/crates/ra-prim/src/xtea.rs": "a5d44f1987dca1382a21a04238ec36235d35b058ce628753d993f923da42769d",
  "/private/tmp/ra-prefix-fix/data/revelations.json": "68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e",
  "research/rev7-20260909-codex/coverage/fable_cascade3_completion_audit/upstream/dictkey2/lib.js": "ffba90a95de78bdeef64c8d2b5602c61d3271e7780914d8322cc5bb9b912ec1d",
  "research/rev7-20260909-codex/coverage/non_mcrypt_history_audit/README.md": "55aaae51f04af5ce52c47e6b170712a68ade86a4e45a9df7d586b89e820f1a7f"
}
```

Run the synthetic controls:

```sh
python3 -B research/rev7-20260909-codex/coverage/tea_controls/controls.py
```

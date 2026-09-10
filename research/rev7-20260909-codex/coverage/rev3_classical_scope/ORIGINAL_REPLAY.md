# Rev3 original recipe: exact replay

```json
{"identity":"ASTRA","rev7_evaluated":false,"status":"exact sibling control verified"}
```

The original recipe on the [Rev3 solution page](https://irebased.github.io/Unsolved-BOIII-Ciphers/ciphers/bo3/rev/rev3/) reproduces the complete plaintext and ciphertext. Reverse the 107 displayed glyphs, map `<=>?@ABCFG` to `0123456789`, then decode the straddling checkerboard using key `FKMCPDYEHBIGQROSAZLUTJNWVX` and spare digits 3 and 7. The decimal/octal character conversion in the original recipe is exactly that glyph-to-digit mapping on this alphabet.

The 61-letter output is:

```
OCTOBERNSAREPORTTTHEYFOUNDTHESOURCEONVENUSBEGINNINGEXTRACTION
```

Re-encoding through the board, inverse glyph mapping, and reversal reproduces all 107 recorded ciphertext characters exactly. The first seven checkerboard tokens are `36 4 72 36 31 9 35`, which decode to `OCTOBER`.

The frozen dataset's alternate plaintext differs at three zero-based offsets: 12 has F instead of P, 21 has W instead of F, and 37 has M instead of V. This evidence package preserves the dataset unchanged and records the discrepancy. It does not imply a ciphertext transcription error.

Reproduction from the repository root:

```sh
python3 -B research/rev7-20260909-codex/coverage/rev3_classical_scope/replay_original.py
```

The script checks the pinned MDX and dataset, constructs the board from the documented key, parses the complete digit stream, checks the expected plaintext, and re-encrypts to the complete ciphertext. `original_replay.json` contains the full board, digit stream, tokenization, plaintext, source hashes, and discrepancy positions.

Rev3 demonstrates why unusual display symbols cannot classify Rev7 as modern encryption. It establishes a working classical chain in a sibling, not that Rev7 uses the same chain. Rev7 has sixteen distinct displayed symbols; this particular ten-symbol mapping cannot be transferred literally.

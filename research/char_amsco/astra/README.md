# ASTRA synthetic character AMSCO geometry

Identity: ASTRA. Target evaluated: false. This package uses generated tokens only; it never reads Rev7 data or invokes cryptography.

The production model treats each hexadecimal character as one token. Cells alternate continuously in sizes `1,2,1,2,...` or `2,1,2,1,...`, including across row boundaries. Cells are assigned row-major to the natural columns, and ciphertext concatenates those columns in the supplied permutation order. The final row may be partial. Only the final cell can be shorter than its nominal size, and no padding is introduced.

The inverse requires the ciphertext length to equal the declared natural length exactly. Both short and trailing-extra ciphertext are rejected.

## Independent controls

`amsco_geometry.py` contains production `forward`, `inverse`, and indexed `inverse_prefix` routines. The independent oracle constructs explicit row objects and token positions with separate forward and inverse implementations; it never calls the production cell generator.

The small grid exhausts lengths 0 through 24, widths 2 through 6, every column permutation, and both alternating starts. Across 43,600 cases it compares production forward output and position labels with the oracle, compares both inverse implementations with the original token stream, and checks every possible indexed prefix. This yields 566,800 prefix comparisons and includes 13,952 genuinely truncated-final-cell cases.

The 1,092-character grid is generated from 546 bytes by `byte[i] = (i*37+11)%256`. It covers:

- the exact four orientations `forward`, full hexadecimal-character reversal, byte reversal, and nibble swap;
- widths 2 through 10 and both starts;
- identity, reverse, and a deterministic shuffled order for each width/start/orientation;
- 216 full inverse cases and 2,799 indexed-prefix comparisons.

The prefix probes include natural positions adjacent to odd ciphertext-column boundaries. Production indexed gather must equal the corresponding prefix from both complete inverses. The complete natural character stream is reconstructed before `bytes.fromhex`, and the decoded 546 bytes must match the independently oriented input bytes.

Because 1,092 is divisible by three, neither alternating start truncates the final cell. There are 728 complete cells. At width 10 the final row has exactly eight cells; this partial row is distinct from a truncated cell. Truncation is covered by the small grid.

A tiny fixture independently fixes the four orientation results for `0123456789AC`:

- forward: `0123456789AC`
- full hexadecimal reversal: `CA9876543210`
- byte reversal: `AC8967452301`
- nibble swap: `1032547698CA`

## Commands

Default verification is read-only and recomputes every synthetic certificate before comparing it with the compact ledger:

```sh
python3 -S -B research/char_amsco/astra/amsco_geometry.py
```

Explicit regeneration refuses an existing output:

```sh
python3 -S -B research/char_amsco/astra/amsco_geometry.py --regenerate /tmp/char-amsco-geometry.json
```

An arbitrary ledger can be checked with `--verify PATH`.

## Limits

This establishes only the stated character-token geometry. It does not claim equivalence to a historical PHP or web implementation. The full-length controls sample three registered orders per context; they do not enumerate widths 7 through 10 factorially. No target ciphertext, cipher, key, IV, detector, or target search is involved.

# Independent review of the AMSCO4 modern-prefix result

Identity: ASTRA. This review did not rerun the 463,680-cell target.

## Accepted mechanics

The geometry is correct for the declared direction. Natural input is 546 bytes = 273 two-byte cells = 39 rows × 7 columns. For a column order `order`, the encoder emits each 78-byte column chunk in rank order. The inverse source index for natural byte `i` is

`rank[floor(i/2) mod 7] * 78 + floor(i/14) * 2 + (i mod 2)`.

An independent Python implementation checked this inverse against a direct encoder for every 5,040 column permutation on 546 labeled indices. All maps were bijections and restored the exact natural sequence.

The executed Cartesian count is exact: 2 input orientations × 5,040 orders × 46 modern contexts = 463,680. The 46 contexts are 19 block ciphers × 2 key spellings plus 4 stream ciphers × 2 spellings. Context records are unique. Both histograms sum to 463,680. The saved extrema agree with their histogram supports: minimum distinct-byte count 83 and maximum printable count 75. No row met `D <= 69 OR printable >= 96`.

The CFB8 IV-forgetting step is sound. For each block cipher the code reconstructs the first `block_size + 128` natural ciphertext bytes, decrypts with ASCII-zero IV, discards exactly one native block, and scores the following 128 plaintext bytes. CFB8 then depends only on the preceding observed ciphertext block, so this 128-byte window is independent of the external IV. Stream contexts skip zero bytes and retain their fixed initialization; they do not carry an all-IV claim.

I replayed all 20 stored best rows through the frozen runtime from their IDs, permutation, orientation, key and cipher. Every stored prefix byte and score matched exactly.

## Concrete defect in auxiliary ranking

The `best_printable` insertion guard compares only `printable` before applying the later sort comparator:

`if (best.length < 20 || score.printable > best[last].score.printable)`.

Once the list is full, a new row tied on printable count is discarded even when its lower `D` or lexical ID would place it inside the declared sort order. The saved histogram has 26 rows above or at the boundary (2 at 75, 1 at 74, 2 at 73, 8 at 72, and 13 at 71), while only seven of the thirteen 71-printable rows can fit. Therefore the first 13 saved entries are necessarily the complete rows with printable ≥72, but the final seven are traversal-dependent members of the 71 tie, not a certified global top-20 under the comparator. This does not affect the exhaustive count, histograms, extrema, or zero-hit result.

## Exact limits

This run applies the inverse of conventional rectangular equal-cut4 columnar emission. It does not test the opposite transposition direction; the inverse family is not generally identical to the encoder family for a 39×7 matrix. `full_hex_reverse` is applied to the observed nibble stream before column reconstruction. The run tests only CFB8 for block ciphers, two fixed key spellings, and the stated 128-byte lead screen. A zero lead count is not a whole-text or universal-language exclusion.

Artifacts checked:

- `search.js`: `eec7380b2ab22db4db523490a75f66a8e0ffa054ac3a95de61b05e5b9a2a4d04`
- `controls.json`: `df09cff8f0db95c405c5583bb593136bd6d736f56b50abf4c27c38d12b1973e5`
- `target_results.json`: `8f5c03bb222db671db9202f374d0b7a516257cbc6a33bf8bea36ddbd67739fbe` (18134 bytes)
- runtime: `fd9d62dd20105757ec41c9affca23375b7276e4bda306feed05eeb0782fd3e30`

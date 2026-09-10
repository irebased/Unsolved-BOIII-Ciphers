# Partial-observation Bifid invariant after lossy CrypTool AMSCO

```json
{"identity":"ASTRA","status":"synthetic controls complete","target_evaluated":false}
```

## Exact model

The hypothetical natural Bifid ciphertext has 1,310 hexadecimal symbols, corresponding to a 655-byte hex-encoded plaintext. A source-certified repeated-label CrypTool AMSCO key emits 1,092 of those symbols. This package uses the frozen inventory's 12 distinct natural-index maps for the 336 qualifying four-digit keys; it does not repeat or alter that classification.

For a displayed orientation, the process is:

1. undo the registered orientation on the 1,092-symbol displayed output;
2. place each symbol at its frozen natural index in a 1,310-slot array, leaving all lost indices `None`;
3. split each **natural** Bifid block at half its actual length;
4. count an ordered pair only when both natural positions are observed.

It is incorrect to pair adjacent positions of the compact 1,092-symbol output or to use 1,092 as the Bifid message length. The Bifid period and final-block geometry apply before the lossy AMSCO emission.

## Lower-bound proof

For an even actual Bifid block, the square-dependent mapping from its first-half/second-half ciphertext-symbol pair to a plaintext byte is bijective, as proved in the pinned parent invariant. Let `K` be the set of distinct ordered pairs for which both natural positions survive. Any completion of the missing symbols has a full pair set `F` with `K ⊆ F`; completing unknown positions cannot remove a fully observed pair. Therefore

```
|K| <= |F| = number of distinct plaintext bytes.
```

If `|K| > 165`, every completion and every square is incompatible with the exact registered 201-codepoint UTF-8 endpoint. A value at or below 165 is unresolved. The proof requires every actual Bifid block to be even and only supplies a necessary condition.

The same monotonic argument applies to the proved construction with distinct fixed ciphertext-coordinate and plaintext-inverse squares. It does not cover unrelated Four-square/two-square algorithms.

## Synthetic controls

Twelve 655-byte valid endpoint plants cover every frozen N=1310 map class once, all four display orientations, and periods 2, 6, 14, 60, and 1310. Seven plants have a short even final block. Every plant contains all 201 allowed codepoints and all 165 possible encoded byte values.

For every plant, the controls:

- encrypt the plaintext hex through a deterministic random 4×4 Bifid square and independently decrypt it;
- emit the natural ciphertext using both a compact literal row/label implementation and the pinned source-faithful CrypTool port;
- match the frozen inventory's complete natural-index list;
- undo the display orientation before reconstruction;
- verify every observed slot against the natural ciphertext and every lost slot as unknown;
- verify the known pair set is a subset of the complete pair set;
- verify the complete pair count equals the plaintext's 165 distinct bytes.

Known pair observations range from 437 to 542. Their distinct counts range from 141 to 165, demonstrating that information loss can lower the bound and that equality with 165 is not an exclusion.

A separate length-12 fixture hides exactly two nibbles and enumerates all `16² = 256` completions. Its four known distinct pairs are present in every completion; the minimum completed distinct count is six. An all-unknown fixture has zero known pairs. These test the lower-bound direction without any language or scoring assumption.

## Reproduction

From the isolated repository root:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/lossy_amsco_controls/controls.py
```

Explicit regeneration refuses an existing output:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/lossy_amsco_controls/controls.py \
  --regenerate /tmp/lossy-bifid-controls.json
```

Frozen artifacts:

- `core.py` SHA-256: `8e71b08333cf9a8d915e45d4d55f8afe09b12031527776ad70aa20fb0a06807d`
- `controls.py` SHA-256: `cc354ef3f2893a142c215f563ddb43c3c30635ee25ca7b9e09cffcad0561fb88`
- `controls.json` SHA-256: `6d5771bacd4f3c18644ad514651ba94f79d0865f89da01ed5365531c1d4279aa` (116,478 bytes)
- source-map inventory SHA-256: `fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2`
- inventory source SHA-256: `6990162132bd5d2d3c77ef3fce00d07c1f807fb33845283021ebbf4fe4323b50`
- source-faithful AMSCO port SHA-256: `ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b`

No Rev7 ciphertext, MDX, or dataset is read by this package. It is a mechanics and proof control only; it contains no target driver or target conclusion.

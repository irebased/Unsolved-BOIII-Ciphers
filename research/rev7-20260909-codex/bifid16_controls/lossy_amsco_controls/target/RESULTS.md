# Lossy AMSCO → even-block arbitrary-square Bifid invariant result

```json
{"identity":"ASTRA","status":"complete","target_evaluated":true}
```

The registered finite inventory completed all 31,440 cells: 12 source-certified N=1310 lossy AMSCO maps × four canonical display orientations × all 655 even Bifid periods from 2 through 1310. The orientation is undone before the 1,092 observed symbols are placed at their natural indices in a 1,310-slot ciphertext. Every Bifid pair is formed within the natural block geometry and counted only when both natural positions are known.

## Exact 201-codepoint result

Every cell has more than 165 distinct fully known ordered pairs. The minimum is 190 and the maximum is 239. Because fully known pairs are a subset of every completion's full pair set, and the even-block Bifid pair transform is bijective for every square, **all 31,440 cells exclude every completion and every arbitrary 4×4 square for the exact registered 201-codepoint UTF-8 endpoint**.

This conclusion also applies to the separately proved construction with distinct fixed ciphertext-coordinate and plaintext-inverse squares. It does not cover unrelated algorithms called Two-square or Four-square.

## Broader Unicode byte-union result

Using the 213-byte union of all well-formed UTF-8 scalar encodings with only TAB/LF/CR and printable ASCII permitted as single-byte values, 11,654 cells are excluded and 19,786 remain unresolved by this invariant:

| Orientation | Cells | Min–max known distinct | Excluded at 165 | Excluded at 213 |
|---|---:|---:|---:|---:|
| forward | 7,860 | 190–239 | 7,860 | 2,885 |
| full hex reverse | 7,860 | 191–239 | 7,860 | 2,946 |
| byte reverse | 7,860 | 192–236 | 7,860 | 2,949 |
| nibble swap | 7,860 | 194–237 | 7,860 | 2,874 |

Each of the 48 map/orientation summaries retains the exact unresolved-period list under both bounds. Each of the 31,440 cell rows retains its 256-bin histogram, known-pair observation count, ordered known-pair stream digest, exact remainder and final-block length, natural placement hashes, and both classifications.

Period 1310 represents every nominal period at or above the natural 1,310-symbol length, including odd nominal periods, because those all produce the same one-block pairing. Odd periods below 1310 are not covered.

## Independent verification

The verifier does not import the parent reconstruction or pair helpers. It independently:

- extracts and matches the canonical 1,092-symbol MDX and dataset text;
- reconstructs each source map directly from its representative key using alternating 2/1 cells, duplicate-label overwrite, and label-order readout;
- undoes each orientation and places the observed symbols into natural positions;
- uses the global plaintext-byte formula to identify each natural first-half/second-half pair;
- recomputes 14,282,448 known pair values and all 8,048,640 histogram bins;
- derives the 165- and 213-byte unions independently from literal codepoints and all Unicode scalar encodings;
- verifies every source pin, cell ID, geometry field, digest, bound classification, and exact unresolved-period summary.

This is a verification-only replay of the saved target-derived counts, not a new square search.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/lossy_amsco_controls/target/pack_results.py
python3 -B research/rev7-20260909-codex/bifid16_controls/lossy_amsco_controls/target/verify_results.py
```

Artifacts:

- target driver: `a6663aca9933ad29148a904f07e6e11773f5d8bc60accd49c4fd1686b9aa613f`
- full result: `cbe78dd96151e19e1e79a689030e436a670fa490075a894150ebfa30183c3744` (41,705,746 bytes)
- independent verifier: `ef8fd5d7bf77d714bedf58bab7528e36609ffb6aa2ed02b9dd865fad241252f0`
- verification ledger: `2a11f5f7e17d85fda5f8821e47e99448d3b17bca252e3dc22f78068f1bfcea54`
- lossless pack: `4cfbd6604c318abe77091df6965464bec85696e6a913e06d0bf9122389f5d9c9` (7,629,124 bytes)
- pack helper: `f9e9b809d8611832220633ca49c8474f7b220d943a64cd1d064c6ea95ea2aaf9`
- compressed payload: `200831e63d0f6a97db34642461b61a4d7d795a44b9a75bafd5321c02f422f8d3` (5,721,579 bytes)
- canonical observed input: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

The pack helper bounds decompression to the declared raw length plus one byte, checks end-of-stream and trailing-data conditions, verifies exact hashes and lengths, and refuses existing restore/build destinations.

## Limits

This result is only the source-certified 12-map, natural-length-1310, even-actual-block invariant. It does not reconstruct lost symbols, identify a square or plaintext, test odd periods below 1310, test other lossy keys/geometries, or cover a transform after Bifid that changes byte distinct-count. Cells unresolved by the broader 213-byte bound are not positive candidates.

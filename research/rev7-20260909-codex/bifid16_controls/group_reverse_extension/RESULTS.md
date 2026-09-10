# Result: width-5 visible-token reversal G

Identity: ASTRA. The preregistered single target execution completed on exec session `51274` with all **1,092/1,092** period cells excluded under bag213. There were **0 unresolved** and **0 incomplete** cells. No search was restarted.

The canonical observed stream SHA-256 is `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`. Its tokens have lengths `[2]+[5]*218`. Independently inverting the visible-token reversal produces the natural stream SHA-256 `c2abbfb1160cb78d4b5f7e39c337a899d739192c8a0f35f34cd877243ddc65c8`.

## Exclusion accounting

- Pair cardinality above 213: 545 cells.
- A single typed graph has no admissible missing-coordinate rectangle: 528 cells. Excluding-type counts: `{"CR": 27, "RC": 501}`.
- Exhaustive coupled typed-rectangle join: 18 cells, periods `[365, 367, 369, 373, 375, 377, 379, 383, 391, 397, 399, 401, 409, 411, 413, 415, 427, 443]`.
- Even empty-rectangle condition: 1 cell, period `[368]`.
- Capped/incomplete: 0.

The run emitted a 900,971-byte result with SHA-256 `65d44a6a765b01e7c9bceaf90c6d612a9a636690882bd3416405fc5a534c9afa` and a 544,836-byte checkpoint with SHA-256 `2abaacb354dec27b8fdc1d53b1849575c29c149eada75ed7702e567ec6d44d1a`. The gate SHA-256 is `d1203bc420268bf75692f935ffb794b3d151c45841f64a1494bcadb3a1f4cce9`.

## Independent replay

`verify_results.py` does not invoke the target driver. It independently reconstructs G from the pinned raw token lengths and a closed-form index permutation; reconstructs every even pair stream and every odd labelled row/column graph; enumerates all 1,820 four-sets for rectangle and single-graph exclusions; and exhaustively replays all 18 completed coupled joins, including candidate counts, obstruction counts, and digests. It also checks the exact 1,092 IDs, checkpoint rows, gate pins, dependency hashes, and canonical sources. The replay passed.

This closes the registered direct Bifid-decryption family for one new G orientation, all periods 1..1092, two fixed 4x4 squares (which may coincide), and the exact bag213 endpoint. It does not cover Bifid encryption direction, other visible-token widths, compositions with global reversal, intervening encodings or binary cipher layers, or endpoints outside bag213.

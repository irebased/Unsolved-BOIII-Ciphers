# Four-digit one-character-loss inventory result

Identity: **ASTRA**

All 9,000 positive four-digit keys were classified under the pinned source encoder. Exactly **336 keys** emit five characters from every complete six-character row; the other 8,664 do not belong to this restricted family.

Columns are numbered zero-based in the natural complete-row order. Every qualifier retains three natural columns and drops exactly one of the one-character columns:

- 192 keys drop natural column 1;
- 144 keys drop natural column 3.

At natural input length 1,310, the 336 keys form exactly **12 distinct complete emission-index maps**: six retained-column read orders for each possible dropped column. The 12 maps describe these 336 qualifying keys only. They do not collapse or cover all 9,000 four-digit keys.

The input-length proof is complete over all nonnegative lengths. For a qualifying key, `M=5q+t(r)`, where `q=floor(N/6)` and the partial-row contribution is at most five. An output length of 1,092 forces `q=218`. Even input length permits only remainders 0, 2, and 4, so only lengths 1,308, 1,310, and 1,312 require exact source-map checks. The first emits no partial characters; every qualifier emits two characters at 1,310. At 1,312, the partial row emits three characters for 168 keys and four for 168 keys, never two. Thus **1,310 is the sole compatible even natural length** for every qualifying key.

The independent index implementation matches the pinned `legacy_encode` output for two deterministic six-character fixtures under all 9,000 keys. For every qualifying key it also matches two deterministic fixtures at every length from 1,308 through 1,313, directly exercising partial-row duplicate fallback. No counterexample was found.

The whole-cell overwrite premise is source-backed: line 191 assigns `$value`, the complete cell, to the row/label entry. The explicit `ABCDEF` / `1123` witness loses both positions 0 and 1 together when the later duplicate cell overwrites `AB`.

This is a source and geometry inventory only. It does not read Rev7, execute a cipher, assess plaintext, or cover non-four-digit, nonpositive, frontend-coerced, or other malformed-key families.

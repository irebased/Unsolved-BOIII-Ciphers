# CrypTool character-AMSCO lossy encoder planning note

Identity: ASTRA  
Status: planning only; no census, cipher experiment, or target evaluation

## Source-faithful row map

Let `d[c]` be the single character/digit at key column `c`. For row `r`, let `t_r` be the number of AMSCO cells actually present: `w` for a full row and possibly less for the final row. The source assignment overwrites by label, so the surviving source column for emitted label `l` is

`L_r(l) = max { c : 0 <= c < t_r and d[c] = l }`.

The encoder output is

`concat(l = 1..w, r in row order, cell[r, L_r(l)] when L_r(l) exists)`.

Full rows share `L_w`. A short final row uses `L_t`. If a repeated label's later occurrence is absent from that final row, an earlier occurrence becomes the survivor. Consequently one emitted label chunk can contain cells from one source column in every full row and a different source column in the final row. A decoder cannot treat every emitted chunk as one unchanged natural column.

For fixed `(w, start, N)`, the behavior signature is the ordered maps `L_w(1..w)` and `L_t(1..w)` together with the deterministic cell positions and sizes. Literal numeric keys with the same signature are observationally equivalent. Earlier overwritten occurrences, absent labels, and characters whose values are not emitted labels cannot be recovered from the output alone. Empty label chunks carry no delimiter.

## Length and host bounds

The frontend casts the submitted key to a PHP integer before later string indexing. This bounds the effective key-string width by the historical host's integer representation. A positive 32-bit PHP integer has at most 10 decimal characters and a positive 64-bit integer at most 19; the actual historical host ABI remains unverified. Signs or other non-label characters produced by accepted numeric syntax act as non-emitted entries under the stated source loop and belong in the effective behavior signature, rather than being treated as new labels.

For a fixed width with at least one emitted label in a full row, output length `M=1092` bounds the number of full rows and therefore bounds input length `N`. Each full row emits at least one token, so a conservative bound is `N <= 2*w*(M+1)` because a row has at most `w` cells and every cell contains at most two tokens. A pattern with no emitted label produces zero output and cannot explain `M=1092`. Thus each fixed-width source-faithful family is finite. The unresolved 32-bit/64-bit host choice changes the finite width bound and must be registered explicitly before exhaustive work.

A correct enumeration should operate on behavior signatures and compatible input lengths, then report how many literal numeric spellings collapse into each signature. It should not present equivalent spellings as independent hypotheses.

## What CFB8 can use

After a candidate signature maps observed characters back to known natural ciphertext positions, CFB8 can recover plaintext only inside contiguous runs of complete known ciphertext bytes. A run of `K` consecutive ciphertext bytes yields `max(0, K-b)` known plaintext bytes for block size `b`: each recovered byte needs its current ciphertext byte and the preceding `b` ciphertext bytes. Scattered cells do not resynchronize CFB8.

Under single-character decimal indexing, only labels `1` through `9` can be emitted, so a row contains at most nine retained cells. For a genuinely lossy full-row pattern:

- an interior known run contains at most nine consecutive retained cells;
- the short-final-row exception can join at most a nine-cell suffix of the last full row to at most nine retained cells in the final row;
- 18 alternating AMSCO cells contain at most 27 hexadecimal characters, which contain at most 13 complete ciphertext bytes.

The conservative direct all-IV bound is therefore at most five terminal plaintext bytes for an eight-byte block cipher and zero bytes for 16- or 32-byte block ciphers. Interior full-row runs contain at most 14 hexadecimal characters, at most seven complete bytes, so they do not resynchronize even an eight-byte CFB primitive.

This bound applies only to direct CFB8 recovery from contiguous known ciphertext under an arbitrary IV. It does not prove the broader puzzle unsolvable. Other constraints could combine multiple partial runs, restrict an IV, exploit a known format, or interact with other layers. Those models require separate controls and scope.

## Smallest practical next experiment

The cleanest next target candidate is the non-lossy subset that the original PHP representation can express exactly:

- widths 2 through 9;
- fixed AMSCO start `21`;
- every valid digit permutation for each width;
- four canonical hexadecimal orientations;
- the ten fixed CFB8 backends already source-controlled.

This is

`4 * sum(w!, w=2..9) = 1,636,448` column-order/orientation cases and 16,364,480 backend contexts.

It excludes width 10 because a single decimal key character cannot encode label `10`. It also excludes invalid repeated-label keys, whose lossy behavior needs the signature model above rather than an invertible column permutation.

The existing synthetic indexed-prefix benchmark suggests about 100 seconds in Python for the narrower five-punctuation endpoint. A conservative all-well-formed-UTF-8 endpoint will do more work per wrong context, so that timing should be replaced by a source-identical synthetic benchmark before preregistration. The grid is still small enough that native implementation is unnecessary unless that benchmark shows otherwise.

## Conservative UTF-8 endpoint

If the necessary condition is broadened to every well-formed UTF-8 byte string, ASCII bytes `00` through `7F` are all accepted, including NUL and controls. The DFA must reject overlong encodings, surrogate encodings, values above `U+10FFFF`, stray excess continuation bytes, and incomplete terminal sequences. It must distinguish:

- code-point boundary;
- one, two, or three generic continuations remaining;
- the restricted first continuation after `E0`, `ED`, `F0`, and `F4`.

Because the all-IV known suffix can start inside an unknown code point, its initial state set is the existential union `{boundary, one remaining, two remaining, three remaining}`. The special first-continuation states are entered only after a corresponding lead byte is observed inside the suffix. At the true message end, only the boundary state is terminal; unfinished multibyte sequences reject.

For uniformly random bytes, the exact counts of complete UTF-8 code-point encodings of lengths one through four are `128`, `1,920`, `61,440`, and `1,048,576`. The asymptotic valid-string fraction decays at approximately `(144.568/256)^n = 0.56472^n`. This remains a strong long-suffix filter despite accepting every ASCII control and NUL, though it will reject later than the five-punctuation rule. A bounded synthetic benchmark must measure actual early-rejection cost for these cipher contexts rather than extrapolating it from the narrower detector.

## Required controls before any target run

1. Reproduce the original PHP overwrite/output order byte-for-byte, including short final rows and accepted integer casts.
2. Compare behavior signatures against literal keys over exhaustive small widths, lengths, repeats, dead characters, and final-row fallbacks.
3. Prove output-length accounting and compatible-`N` enumeration independently.
4. Validate known natural-position masks and every reported contiguous complete-byte run with a separate materialized oracle.
5. Validate the complete UTF-8 DFA against an independent decoder for valid 1-, 2-, 3-, and 4-byte boundary cases, overlongs, surrogates, maximum scalar value, out-of-range values, truncated endings, and suffixes beginning with one to three continuation bytes.
6. Keep the valid-permutation experiment and lossy-signature experiment as separate preregistered families with separate conclusions.

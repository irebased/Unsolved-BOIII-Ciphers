# Typed empty-rectangle condition for odd-block 4x4 Bifid

Identity: **ASTRA**. This is target-free mathematics and synthetic control evidence.

Let the ciphertext-coordinate square be `Sc` and the plaintext-output square be `Sp`; they may be the same fixed square or two distinct fixed squares. Flatten each ciphertext symbol into its row and column digits. For an actual block of length `L`, plaintext nibble `i` is

```text
Sp^-1(D[i], D[L+i]).
```

Tag each selected digit by its axis and originating ciphertext symbol. Every global even plaintext-nibble position (a byte's high nibble) therefore gives a directed typed edge `(a,b,XY)`, where `X,Y` are `R` or `C`. For an odd block starting at an even global nibble, internal high nibbles are `RC(row(a),col(b))`. For an odd block starting odd they are `CR(col(a),row(b))`. The high nibble of the boundary byte before an odd-start block is the preceding even-start block's final `RC` nibble. A generic even block produces `RR` when its relevant local parity is even and `CC` when odd; the standard even-length tail of an odd-period, even-length message starts even and therefore uses `RR`. The generic flattening equation, implemented directly in the control, handles every short block without a special-case guess.

Bag213 contains no byte with high nibble `1`. If symbol `1` is at coordinate `(u,v)` in `Sp`, every typed graph must omit its corresponding class rectangle:

```text
G_RC omits RowSc(u) × ColSc(v)
G_CR omits ColSc(u) × RowSc(v)
G_RR omits RowSc(u) × RowSc(v)
G_CC omits ColSc(u) × ColSc(v).
```

For same-axis types the two four-symbol classes are equal when `u=v` and disjoint otherwise. For cross-axis types they intersect in exactly one symbol. The `RC` and `CR` tests are coupled through the same ordered coordinate `(u,v)`: when `u != v`, `Row(u)×Col(v)` and `Col(u)×Row(v)` are different directed rectangles and cannot be freely swapped.

A single typed graph suffices if it has no permitted empty 4x4 rectangle for any square partition and `(u,v)`. The stronger arbitrary-set relaxation from the even proof also suffices: if a graph has no empty rectangle for any two four-symbol sets at all, no square geometry can rescue it. Failure of a single-graph test is inconclusive. Intersecting the `(u,v)` candidates from all typed graphs is stronger; the controls include graphs whose individual candidate sets are `{(0,0)}` and `{(1,1)}` but whose joint set is empty.

For two distinct fixed squares, `(u,v)` can be any coordinate occupied by `1` in `Sp`, but it must be the same coordinate across all types. For the one-square case `Sp=Sc`, `(u,v)` is additionally the coordinate of ciphertext symbol `1` under the same partition, so the one-square condition can be stronger. Any no-rectangle certificate proved under the less constrained two-square model also applies to the one-square model.

This theorem is a necessary high-nibble condition only. A surviving rectangle does not construct either square or ensure remaining bytes belong to bag213/UTF-8. A target-wide exclusion with unknown `Sc` would have to quantify over all valid row/column partitions and the coupled coordinate; examining one convenient partition is insufficient. No Rev7 ciphertext, period, or solver search is used here.

`controls.py` independently extracts typed edges from the generic flattened stream, compares them with concrete decryption under 80 same/distinct-square fixtures, covers odd blocks, short tails and mixed-parity `RR/CC`, checks class intersections, and exercises both single-graph and combined-graph certificates.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_typed_rectangles/controls.py
```

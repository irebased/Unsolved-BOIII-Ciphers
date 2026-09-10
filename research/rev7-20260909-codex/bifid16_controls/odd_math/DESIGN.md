# Odd-period 4×4 Bifid byte geometry

```json
{"identity":"ASTRA","status":"synthetic mathematical assessment","target_evaluated":false}
```

## Source convention

This uses the same explicit 4×4 generalization of the mirrored CrypTool Bifid fractionation: ciphertext coordinate pairs are flattened, the length-`2L` digit stream is split at `L`, and the two halves are interleaved into plaintext coordinate pairs. The historical helper is `/private/tmp/rev7-fable-20260909/cto_legacy/_ctoLegacy/tools/bifid/functions.bifid.php`, SHA-256 `fb4542ac9e3320d83cb41020a8548842e7f8850c24674a1399dc28b210c0234c`. The PHP square itself is 25-symbol; this note is a mathematical 16-symbol generalization.

## One odd block

Let an actual block have length `L=2h+1`, and let ciphertext symbol `C[j]` have square coordinates `(r_j,c_j)`. Directly indexing the flattened coordinate stream gives

```
P[2j]   = S^-1(r_j, c_(h+j))       0 <= j <= h
P[2j+1] = S^-1(c_j, r_(h+j+1))     0 <= j < h.
```

This confirms the proposed local formula. It is not yet a byte formula until the block's start parity in the global plaintext nibble stream is known.

For an odd nominal period, successive full odd blocks alternate their global nibble-start parity. An even-start block has internal bytes `(P[2j],P[2j+1])`; an odd-start block has internal bytes `(P[2j+1],P[2j+2])`. Every boundary after an even-start odd block contributes a byte whose high nibble is the previous block's final `P[2h]` and whose low nibble is the next block's `P[0]`. The next boundary is byte-aligned.

For an even-start odd block, an internal byte derived from `a=C[j]`, `b=C[h+j]`, `c=C[h+j+1]` has output-coordinate signature

```
(row(a), col(b), col(a), row(c)).
```

For an odd-start odd block, an internal byte derived from `a=C[j]`, `b=C[h+j+1]`, `c=C[j+1]` has signature

```
(col(a), row(b), row(c), col(b)).
```

At a crossing into another odd block, the prior high nibble has coordinates `(row(C[h]),col(C[2h]))`; the next low nibble has `(row(C'[0]),col(C'[h']))`. Their concatenation is the four-coordinate signature. The generic flatten/split equations remain authoritative for a differently sized final block.

## Inverse-free distinct-byte formulation

For every global plaintext nibble `t`, retain its two output coordinate digits `Q[t]=(u_t,v_t)` before applying `S^-1`. Define byte signature

```
Z[j] = (u_(2j), v_(2j), u_(2j+1), v_(2j+1)).
```

The inverse square is a bijection from 16 coordinate positions to the 16 canonical hex symbols. Therefore

```
plaintext_byte[j] == plaintext_byte[k]  iff  Z[j] == Z[k].
```

This holds for internal bytes, cross-block bytes, odd blocks, even tails, and mixed block-start parity. Consequently the exact plaintext distinct-byte count for a proposed square is the number of distinct four-coordinate signatures. A solver never needs the 16-way inverse lookup merely to enforce a distinct-byte bound.

A compact QF_BV/table model can use one four-bit position variable `k_s` per ciphertext symbol, constrain the 16 positions `AllDifferent`, and derive `row_s=k_s>>2`, `col_s=k_s&3`. The flatten/split index equations select the four two-bit components of each `Z[j]`. For each possible eight-bit signature value `v`, a Boolean `used_v` is equivalent to `OR_j(Z[j]=v)`; `sum used_v <= 165` is the exact registered byte-union necessary condition. The same scheme supports 213.

This removes the inverse-square selection from the byte-equality expression. Encoding size and runtime are unmeasured: a direct `used_v` formulation introduces up to 256×N byte equalities plus cardinality machinery and may be larger or slower than an inverse lookup formulation. The row/column variables remain coupled by the permutation constraint, and 546 signatures share them.

## Internal subset bound

The even-start signature identifies `a` from the output rows: `(row(high),row(low))=(row(a),col(a))`. Thus output sets for different fixed `a` are disjoint, and the number of distinct internal outputs in that subset is exactly

```
sum_a |{ (col(b),row(c)) observed with this a }|.
```

The odd-start formula similarly identifies fixed `b` from `(col(high),col(low))`, giving

```
sum_b |{ (col(a),row(c)) observed with this b }|.
```

Each expression is a sound lower bound on the whole plaintext's distinct-byte count, but it still depends on the unknown row/column partitions. Without solving those partitions, the generally guaranteed contribution can collapse to roughly the number of distinct anchor symbols, at most 16, far below 165. Results from the even-start and odd-start subsets also cannot simply be added because their output signatures may overlap. The formulas are useful propagation/objective constraints, not a standalone target exclusion.

## Synthetic checks

`odd_math.py` is self-contained and reads no Rev7 data. For 24 deterministic random squares it exhaustively constructs all `16³=4096` internal triples for each global parity, checks the coordinate signatures against concrete inverse-square outputs, and verifies all 16 anchor groups are pairwise disjoint. It then tests every odd period 3..31 on every even message length 32..96.

Across 11,880 period/message comparisons, concrete Bifid decryption and coordinate signatures had identical byte-equality partitions and distinct counts. Checks covered 174,432 even-start internal bytes, 147,792 odd-start internal bytes, 34,776 cross-block bytes, 5,568 short odd tails, and 5,256 short even tails.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_math/odd_math.py
```

- source SHA-256: `d4c60fabfb8335140564f5c15135d16dab484fb57d11867a6ede145748d9b925`
- result SHA-256: `899b368f0cbae05297074982d89390e82271cf65fc699218e95098ec63b36265`

## Assessment and limits

The inverse-free signature formulation is algebraically useful: it removes per-position inverse-square lookup and exactly represents the distinct-byte objective across odd blocks and boundaries. No size or speed advantage has been established. The anchor-subset sums may offer early lower-bound propagation. Neither supplies a square-independent numerical exclusion comparable to the even-block bijection without optimizing the unknown coordinate assignment.

No solver, Rev7 ciphertext, target period, or practical-runtime claim was evaluated. The equations cover one-square flatten/split/interleave Bifid only. They do not cover alternative fractionation, inserted/deleted symbols, an odd-length overall hex stream, or downstream transforms that alter distinct-byte equality.

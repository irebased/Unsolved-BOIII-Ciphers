# Square-independent invariant for even Bifid blocks

```json
{"identity":"ASTRA","status":"proved and synthetically checked","target_evaluated":false}
```

## Result

For the one-square 4×4 Bifid equations in `DESIGN.md`, every ciphertext block whose **actual symbol length is even** induces the same kind of square-dependent but bijective map from an ordered pair of ciphertext symbols to one plaintext byte. Consequently, within any message made entirely of even-length Bifid blocks,

```
number of distinct paired ciphertext-symbol pairs
  = number of distinct decoded plaintext bytes
```

for every possible 4×4 square. This is a square-independent necessary condition; it does not recover the square or plaintext.

## Proof

Let an actual block have length `L=2h`, and let ciphertext symbol `C[j]` have square coordinates `(r_j,c_j)`. Flattening the ciphertext coordinates gives

```
D = r_0,c_0,r_1,c_1,...,r_(L-1),c_(L-1).
```

CrypTool-style Bifid decryption pairs `D[i]` with `D[L+i]`. Because `L` is even, both indices have the same parity. Therefore plaintext positions `2j` and `2j+1` are

```
P[2j]   = S^-1(r_j, r_(h+j))
P[2j+1] = S^-1(c_j, c_(h+j)).
```

Define the ordered-pair transform

```
F_S(a,b) = (S^-1(row(a),row(b)), S^-1(col(a),col(b))).
```

The two output symbols are one canonical hexadecimal byte. `F_S` is an involution. If `F_S(a,b)=(x,y)`, then the square coordinates of `x` are `(row(a),row(b))` and those of `y` are `(col(a),col(b))`; applying `F_S` again returns `(a,b)`. Hence `F_S` bijects the 256 ordered input pairs with all 256 plaintext bytes and preserves distinct-count exactly.

The same `F_S` applies to every block because the square is global. Block length changes only which first-half symbol is paired with which second-half symbol.

The distinct-count result does not actually require the ciphertext coordinate square and plaintext inverse square to be identical. For fixed squares `S_C` and `S_P`, define

```
F_(C,P)(a,b) = (S_P^-1(row_C(a),row_C(b)),
                S_P^-1(col_C(a),col_C(b))).
```

Given output `(x,y)`, the explicit inverse is

```
a = S_C^-1(row_P(x),row_P(y))
b = S_C^-1(col_P(x),col_P(y)).
```

Thus this two-fixed-square coordinate construction is also a bijection and obeys the same distinct-count invariant. It need not be an involution. This is a mathematical generalization of the stated coordinate construction; it must not be conflated with every cipher called two-square Bifid, Four-square, or another fractionation algorithm.

The condition is about actual block lengths, not merely whether the nominal period is even. For even total length `N`:

- any even period below `N` produces even full blocks and an even remainder, so all actual blocks qualify;
- any period `p >= N` produces one actual block of length `N`, so it qualifies even when `p` is odd;
- an odd period below `N` creates at least one odd full block, where the parity step in the proof fails.

For Rev7's reported `N=1092` hex symbols, every even period qualifies, and every nominal period at least 1092 is equivalent here to one whole-message block. This is only a geometric statement; this package does not read or count Rev7 pairs.

## Endpoint bounds

For the exact 201-codepoint endpoint used elsewhere—TAB/LF/CR, printable ASCII, U+00A0..U+00FF, and seven registered punctuation codepoints—the union of possible UTF-8 byte values has size 165:

- 98 permitted one-byte ASCII values;
- lead bytes `C2`, `C3`, and `E2`;
- all 64 continuation values `80`..`BF`.

Thus a qualifying paired-ciphertext stream with more than 165 distinct ordered pairs cannot decode under any square to that endpoint. This is only a necessary byte-union bound; counts at or below 165 remain unresolved and still require proper UTF-8 sequencing.

A broader well-formed-UTF-8 endpoint that keeps the same ASCII restriction but allows all Unicode scalar values has a 213-byte union: 98 ASCII values, 64 continuation bytes, and 51 valid multibyte lead bytes `C2`..`F4`. More than 213 distinct pairs excludes that broader endpoint. The 30 excluded ASCII byte values are controls other than TAB/LF/CR plus DEL. Again, this is a byte-union necessary condition, not a language proof.

A future target inventory may preserve, for each period/orientation, the full ordered-pair histogram as well as its distinct count. Periods yielding the same block partition should be deduplicated explicitly. No target count was made here.

## Synthetic verification

`even_period_invariant.py` is self-contained and does not import the earlier probe. For 32 deterministic random same-square cases it enumerates all 256 ordered pairs, asserts 256 distinct outputs, and applies the map twice to every pair. Another 32 independently randomized ciphertext-square/plaintext-square pairs enumerate all 256 inputs and check the explicit inverse above. It then compares the pair formula byte-for-byte with literal coordinate-flatten/split/interleave Bifid decryption across:

- every even message length from 2 through 128;
- every even nominal period from 2 through 64;
- 41,728 cases with a positive short even tail;
- every odd nominal period from `N` through `N+15`, which exercises the one-actual-even-block case.

All 81,920 concrete comparisons passed. The result ledger stores every square and its complete pair-map digest.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/even_period_invariant.py
shasum -a 256 \
  research/rev7-20260909-codex/bifid16_controls/even_period_invariant.py \
  research/rev7-20260909-codex/bifid16_controls/even_period_invariant.json
```

- source SHA-256: `1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2`
- ledger SHA-256: `f6f2d01801992bb145c583fdc83284ea100c99d30bf4f3e5a477b56317a84a36`
- historical fractionation source SHA-256: `fb4542ac9e3320d83cb41020a8548842e7f8850c24674a1399dc28b210c0234c`

## Limits

The proof requires the exact one-square coordinate flatten/split/interleave convention and even actual block lengths. It does not apply to odd blocks, arbitrary algorithms merely named two-square/Four-square, alternative fractionation order, nonhex plaintext-symbol interpretation, inserted/deleted symbols, or a downstream transform that changes byte distinct-count. Passing the bound proves nothing about readability or square existence.

# Arbitrary-square 4×4 Bifid constraint design

```json
{"identity":"ASTRA","status":"synthetic design only","target_evaluated":false}
```

## Scope and source anchor

This note generalizes the fractionation equations in the mirrored 2008 CrypTool Bifid helper to a 16-symbol alphabet. It does **not** claim that the historical PHP tool supported 4×4 squares. In the source, `encodePolybios` maps each symbol to a coordinate pair (lines 41–47), `encodeNumbers` concatenates all first coordinates followed by all second coordinates (lines 30–38), and `decodeNumbers` splits that digit stream in half and interleaves the halves (lines 18–27). `createPolybiosSquare` itself uses `$alfa25` (lines 56–67).

Source: `/private/tmp/rev7-fable-20260909/cto_legacy/_ctoLegacy/tools/bifid/functions.bifid.php`; SHA-256 `fb4542ac9e3320d83cb41020a8548842e7f8850c24674a1399dc28b210c0234c`.

The proposed hypothesis takes both ciphertext and Bifid plaintext symbols from `Σ = 0123456789ABCDEF`. After Bifid decryption, adjacent plaintext symbols are interpreted as canonical hexadecimal nibbles and decoded to bytes. Those bytes, rather than the intermediate symbols individually, are tested by a declared allowed-UTF-8 automaton. This distinction must be frozen before any target run. An odd nibble count or a leading-zero restoration policy is outside this design unless separately registered.

## Exact decryption equations

Let `k_s ∈ {0,…,15}` be the square position of symbol `s`, with `AllDifferent(k_s : s∈Σ)`. Define

```
r_s = k_s div 4
c_s = k_s mod 4
```

For a ciphertext block `C[0:L]`, form the length-`2L` coordinate stream

```
D[2j]   = r_(C[j])
D[2j+1] = c_(C[j])                 for 0 <= j < L.
```

CrypTool-style decryption splits this stream at `L`. For plaintext position `i`,

```
R_i = D[i]
Q_i = D[L+i]
k_(P[i]) = 4*R_i + Q_i             for 0 <= i < L.
```

Because `k` is a bijection, `P[i]` exists and is unique. For period `p`, apply these equations independently to blocks beginning at `a = 0,p,2p,…`, with `L=min(p,N-a)`. The last short block therefore uses its own split point `L`; padding it to `p` would be a different cipher. A length-one block is the identity. If every block has length one, the square is completely unidentifiable.

For even `N`, endpoint byte `B[j]` is

```
B[j] = 16*value(P[2j]) + value(P[2j+1]),
```

where `value` is the ordinary hex value of the symbol, independent of its square coordinates. Feed `B` to the exact allowed-UTF-8 DFA and require its declared start/end conditions. This couples two recovered Bifid symbols at a time and avoids treating permissible UTF-8 bytes as an independent byte bag.

## Exact 24-fold symmetry

For any permutation `π` of the four coordinate labels, replace every square coordinate `(r_s,c_s)` with `(π(r_s),π(c_s))`. The ciphertext coordinate stream becomes `π(D)` element by element. Each recovered pair becomes `(π(R_i),π(Q_i))`, and the relabelled inverse square maps that pair back to the same symbol `P[i]`. Thus all 24 elements of the diagonal `S4` action preserve the complete plaintext for every period and final-block length.

The action is free on a full 4×4 square: a nonidentity `π` moves at least one coordinate label, and the square contains every ordered coordinate pair. Hence complete squares form orbits of exactly 24 and a search may use one canonical representative per orbit, reducing `16!` to `16!/24 = 871,782,912,000` representatives without loss.

A convenient solver-neutral symmetry break scans

```
r_0,c_0,r_1,c_1,...,r_F,c_F
```

and requires the first distinct coordinate label encountered to be `0`, the next previously unseen label `1`, then `2`, then `3`. Every diagonal orbit has exactly one such relabeling.

Independent row and column relabelings are **not** generally plaintext-preserving. With the identity square, period 2, and ciphertext `00`, swapping row labels 0 and 1 while leaving columns fixed changes the decryption from `00` to `14`. Transposing the identity square changes ciphertext `01`, period 2, from plaintext `01` to `40`. Period-one blocks can have larger accidental symmetry, but that does not justify a larger symmetry quotient for general periods.

## Constraint encodings

A compact SMT/CP model can use the 16 integer variables `k_s`, one `AllDifferent`, derived `div/mod` coordinates, and an element/inverse constraint for every plaintext position:

```
Element(k, P[i]) == 4*D[i] + D[L+i].
```

Each two-symbol plaintext pair defines a byte, followed by a regular-language/DFA constraint for the UTF-8 endpoint. A SAT version can instead use 256 one-hot literals `X[s,q]` with exactly-one constraints for each symbol and square position; coordinate and inverse lookups become table clauses. Symmetry breaking is expressible with first-occurrence auxiliary variables.

A direct DFS has only 16 assignment levels and can propagate the same facts without a general solver: maintain the partial symbol↔position bijection, instantiate every `D` digit whose ciphertext symbol is assigned, force inverse symbols when both output coordinates become known, reject assignment conflicts immediately, and advance the hex-byte UTF-8 DFA whenever both plaintext nibbles are fixed. Each rejected depth-`d` partial bijection represents `(16-d)!` full assignments only when the traversal branches disjointly and the symmetry quotient/accounting is implemented consistently.

No performance or completeness claim is made here. SMT offers a concise independently checkable formulation and model blocking for all survivors; custom DFS can exploit repeated ciphertext symbols and early endpoint transitions more directly. A controlled next step would compare both on synthetic planted squares and short exhaustive alphabets before selecting an engine. Neither approach should start from a blind `16!` loop.

## Synthetic evidence

Run from the isolated repository root:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/symmetry_probe.py
shasum -a 256 \
  research/rev7-20260909-codex/bifid16_controls/symmetry_probe.py \
  research/rev7-20260909-codex/bifid16_controls/symmetry_results.json
```

The probe implements the equations above, including final short blocks. Sixteen deterministic synthetic plants round-trip under varied squares, lengths, and periods. Their plaintext is invariant under all 24 diagonal relabelings (384 checks). It also records the two minimal counterexamples above. It reads no Rev7 input.

- `symmetry_probe.py` SHA-256: `8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0`
- `symmetry_results.json` SHA-256: `c85649306729315d49cbca7c0ab6888b619bfa3c59eb35cc9d39810c8e017f89`

## Limits

This formulation covers one-square 4×4 Bifid with a fixed period and a hex-decoded UTF-8 endpoint. It does not cover two-square/conjugated variants, Nihilist arithmetic, Four-square, unknown pre/post substitutions, odd-nibble framing, alternative fractionation conventions, or arbitrary-depth chains. The 24-fold symmetry is proven for the stated equations; no larger general quotient is asserted.

# Next test for the cut-4 `ZOMBIES` repeat lead

```json
{"identity":"ASTRA","status":"design only","target_evaluated":false}
```

## What is established

The fixed conventional equal-cut geometry is exact: 1,092 hex symbols form 273 indivisible four-symbol cells, a `39 × 7` rectangle, and `ZOMBIES` gives column order `[3,5,4,2,1,6,0]`. Conventional forward-input decode produces SHA-256 `1cb32555f497309352adec7f5757bc3e9f5fb02fe077995ae0b83ff3a052d1be`.

On that stream, `030E6` occurs at zero-based positions 828 and 942. It is one left- and right-maximal repeated region with gap 114. Its nested `030E`, `30E6`, and `030E6` rows explain the supplied 3/3/3 supports because `114 = 6×19 = 3×38 = 2×57`. Collapsing the nested rows leaves one observation, not three independent peaks.

There is no rigorous matched-null calibration of this collapsed statistic in the reviewed corpus. The accepted Kasiski report explicitly records no null distribution or significance estimate. The reported 200-null FABLE calculation used its own unreproduced statistic, did not reproduce the contributor's support counts, and therefore does not calibrate this precise collapsed-region statistic. The hypothetical Poisson illustration is also not a calibration.

Two direct periodic explanations of the same decoded stream are already closed under the declared 165-byte necessary endpoint: byte XOR/subtraction keys at periods 19, 38, and 57, and the relaxed paired-nibble subtraction/Beaufort families containing nibble periods 19, 38, and 57. Repeating those grids would add no evidence.

The complete two-fixed-square 4×4 Bifid result covers four orientations of the canonical 1,092-symbol input, periods 1 through 1,092, direct standard decryption, and bag213. It does not include the AMSCO-decoded stream above. Thus AMSCO-decode followed by arbitrary-square Bifid is technically new, but the repeat observation supplies no particular Bifid-square or period model. A four-symbol-cell transposition also preserves the 546 original byte pairs as a multiset, so applying only this AMSCO and then a direct byte-bag test cannot rescue bytes outside the bag.

## One recommended bounded experiment

Run an **exact 7! column-order census**, with no random simulation:

1. Fix the canonical input, four-symbol cells, `39 × 7` rectangle, conventional decode direction, and forward input.
2. Enumerate all 5,040 distinct permutations of the seven column chunks. This includes the `ZOMBIES` order exactly once.
3. For each output, enumerate left/right-maximal repeated occurrence-pair regions of length at least four.
4. Retain regions whose gap is divisible by `lcm(19,38,57)=114`.
5. Record every witness, the number of qualifying regions, and the maximum qualifying length. Compare `ZOMBIES` by the predeclared lexicographic statistic `(maximum length, region count)`, with full tie counts and its exact rank among 5,040.

This is the smallest useful calibration because it directly asks whether the chosen key order is exceptional within the exact fixed geometry that generated the lead. It is exhaustive and avoids PRNG or Monte Carlo error. It does **not** produce a global p-value: the four-symbol cut, decode direction, forward orientation, periods, minimum length, and the `ZOMBIES` key were selected after an unknown broader search. A fixed-multiset shuffle null would still leave that selection problem and is unnecessary before this exact conditional census.

## Controls and retained evidence

The implementation should have two independent maximal-repeat routines on small fixtures: a slow all-pairs extender and a suffix/subsequence implementation used for the census. Controls must include nested and shifted overlaps that collapse to one region, three occurrences yielding three occurrence pairs, a planted length-five region at gap 114, no-repeat inputs, and equality of all witnesses on exhaustive short strings over a tiny alphabet. Geometry controls must prove each of the 5,040 orders is a permutation of all 273 cells and reproduce the existing `ZOMBIES` stream hash and `030E6` witness before the census is accepted.

Retain all 5,040 compact rows, the full distribution, tie/rank convention, source/runtime hashes, and the exact command. No language score, cipher key inference, Bifid claim, or Rev7 plaintext claim follows from the rank alone.

## Evidence paths

- `coverage/kasiski44/REPORT.md`: exact four-context repeat inventory and explicit absence of a null model.
- `coverage/kasiski44/maximal_repeats.py` and `.json`: accepted collapse definition and complete witnesses.
- `coverage/kasiski44/independent_witness.py` and `.json`: independent source-index reconstruction of the `030E6` region.
- `coverage/kasiski44/periodic_followup/RESULTS.md`: exact byte-period exclusions on the decoded stream.
- `coverage/kasiski44/nibble_additive_target/RESULTS.md`: exact relaxed nibble-period exclusions on the decoded stream.
- `bifid16_controls/odd_rectangle_join_target/COVERAGE_FINAL.md`: direct canonical-input two-square Bifid scope and limits.

Exact reviewed file hashes are frozen in `evidence.json`.

# Equal-cut-4 `ZOMBIES` geometry and exact repeat-gap inventory

```json
{"identity":"ASTRA","status":"four registered contexts complete","target_evaluated":true}
```

## Geometry

With both AMSCO cuts equal to four symbols, the 1,092-symbol input forms 273 indivisible four-symbol cells. Seven columns give an exact `39×7` rectangle, so no ragged-row convention is involved. For key `ZOMBIES`, alphabetical key-letter order is `B,E,I,M,O,S,Z`, corresponding to zero-based source columns

```
3, 5, 4, 2, 1, 6, 0.
```

`geometry.py` implements both directions explicitly. `encode` fills cells row-wise and emits columns in that order; `decode` treats the input as those seven 39-cell column chunks and restores row order. Synthetic controls verify both inverse round trips, all 1,092 natural-index positions exactly once, and a labelled two-row example on which the directions differ.

This geometry is exact for the stated equal cuts and conventional keyed-column order. It does not establish which direction or input reversal an outside program used.

## Exact four-context statistic

The registered analysis applies `encode` and `decode` to both the canonical input and its full 1,092-symbol reversal. For n-gram lengths 3, 4, and 5, it visits every start position, groups identical n-grams, and retains every unordered pair of distinct occurrence positions. A pair supports candidate period `p` exactly when `p` divides its position gap.

| Context | Transformed SHA-256 | Repeat pairs n=3/4/5 | Supports 19/38/57 | Supports all three |
|---|---|---:|---:|---:|
| encode, forward | `3f44a5a11942b7558cb1a68984d38700152e20cfdee3031ad2d147fb15cd6f86` | 125 / 11 / 0 | 4 / 2 / 2 | 1 |
| encode, full reversed input | `948fdf874f4f2253ff2dbdcd70df0bd8a4adfb0d3733cf03fea0cb3541632cc9` | 125 / 11 / 0 | 2 / 1 / 2 | 1 |
| decode, forward | `1cb32555f497309352adec7f5757bc3e9f5fb02fe077995ae0b83ff3a052d1be` | 144 / 9 / 1 | 11 / 9 / 9 | 8 |
| decode, full reversed input | `8de8f735aa5e5873772892feaa7defd0b9330a8311dc751cf02be2f8d7081b8e` | 136 / 5 / 0 | 6 / 3 / 2 | 1 |

The result ledger retains every repeated n-gram, both starts, gap, supported-period list, complete gap histograms, and pair-set intersections.

The combined n=3/4/5 counts do not equal the supplied outside-program supports `3,3,3`, but one precise aggregation **does**: in `decode:forward`, counting the two supported 4-gram rows plus the one supported 5-gram row gives exactly `3/3/3` for periods 19/38/57. The rows are `030E` at starts 828/942, `30E6` at 829/943, and `030E6` at 828/942; every gap is 114. This is a strong plausible explanation of the supplied support counts if that program aggregates n-grams of length at least four without collapsing nested repeats.

Per n-gram length in `decode:forward`, the exact support counts are:

| n | period 19 | period 38 | period 57 |
|---:|---:|---:|---:|
| 3 | 8 | 6 | 6 |
| 4 | 2 | 2 | 2 |
| 5 | 1 | 1 | 1 |
| 4 and 5 combined | **3** | **3** | **3** |

This package still does not reproduce the supplied `Z` scores. The program name, expected-count model, overlap handling, and precise aggregation rule remain unknown, so the match is evidence for a likely convention rather than proof of implementation identity.

## Dependence among 19, 38, and 57

The periods are arithmetically nested rather than independent observations:

- every gap divisible by 38 also supports 19;
- every gap divisible by 57 also supports 19;
- a gap divisible by `lcm(38,57)=114` supports all three.

The synthetic occurrence starts `0,114,228` produce the three pairs `(0,114)`, `(0,228)`, and `(114,228)` with gaps `114,228,114`; each pair supports all of 19, 38, and 57. This example is asserted in `analyze.py` and retained in `results.json`.

Overlap across n-gram lengths adds further dependence. In `decode:forward`, one repeated `030E6` at gap 114 simultaneously contributes repeated trigrams `030`, `30E`, `0E6`, four-grams `030E`, `30E6`, and the five-gram itself. Six support rows therefore arise from one repeated five-symbol region, not six independent repetitions. The other two all-period rows are trigrams `267` and `C42`, also at gaps divisible by 114.

A separate maximal-repeat pass collapses shifted/nested rows on the same occurrence-pair diagonal. In `decode:forward`, its exact supporting regions are:

| Period | Left/right-maximal repeated regions `(text, starts, gap)` |
|---:|---|
| 19 | `BD7` (2,724,722); `267` (168,282,114); `C42` (209,665,456); `5B3` (341,740,399); `600` (519,652,133); `030E6` (828,942,114) |
| 38 | `BD7` (2,724,722); `267` (168,282,114); `C42` (209,665,456); `030E6` (828,942,114) |
| 57 | `267` (168,282,114); `C42` (209,665,456); `5B3` (341,740,399); `030E6` (828,942,114) |

Thus maximal-repeat support is 6/4/4, while the intersection common to all three periods is exactly three regions: `267`, `C42`, and `030E6`. Restricting maximal repeats to length at least four collapses the nested n=4/5 rows to one common region, giving 1/1/1. These alternatives show why the aggregation definition matters.

Period 19 is not disqualified because it does not divide 1,092. Kasiski-style gap support concerns distances between repeated substrings; it does not require a period to divide the entire message length.

## Reproduction and hashes

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44/controls.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44/analyze.py
shasum -a 256 research/rev7-20260909-codex/coverage/kasiski44/*
```

The second command is a read-only scope/preflight after the one registered run. The completed result is already present and the source refuses overwriting it.

- geometry source: `cad6c29e75cc1d43ba9f43d172767c081bed8b0394ce5ae7c8adee3e22427e61`
- synthetic controls source: `b1e930ddd36b2e3e23dcec86f8d7951dbdb964ae6b7a6a8f68ab56bf34f48c33`
- controls ledger: `17cc743f29378bc938698b7bb83d55d0b3db5800db0116a3fbbe7407b6d1da00`
- canonical analysis source: `38f1125465d9620f3f9b589ccb825cc6b0f102c663091b55e0fdfafeb649ebe8`
- result ledger: `b3aa68a0a1950c7475dcd22f91353261096bf8d561892b8c09b8feb9b47d45b0` (124,313 bytes)
- maximal-repeat verifier: `32d08db3a4e1252c25f7448c44bc46774c3fc3b1e5ee1927a347ff716c222b37`
- maximal-repeat ledger: `d19ddbe0b7b3fd41c3c168833e6b7562a56968f4e3f5cc5528f96828abd0fb9e`
- canonical normalized input: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

## Limits

This is a deterministic geometry and repeat-gap inventory. It has no language score, random null, significance estimate, cipher-key inference, or negative conclusion. It does not identify the external program's statistic, and the supplied `Z` values should not be compared numerically until that implementation or formula is known. Full input reversal is tested as a separate input context; it is not silently equated with swapping encode/decode direction.

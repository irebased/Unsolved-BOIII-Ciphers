# Exact key-order census for the cut-4 repeat lead

```json
{"identity":"ASTRA","status":"controls complete; target not run","target_evaluated":false}
```

This package implements the bounded conditional comparison proposed in `coverage/kasiski44_next_design/`. It fixes the canonical forward input, 273 indivisible four-symbol cells, 39 rows, seven columns, and conventional columnar decode. The only varying parameter is the lexicographically enumerated read-column permutation, giving exactly `7! = 5,040` streams. The `ZOMBIES` order is `[3,5,4,2,1,6,0]`.

For each stream, the target driver finds every occurrence pair sharing a four-symbol seed, rejects pairs that can extend left, and extends the rest maximally to the right. A witness qualifies when its maximal length is at least four and its gap is divisible by `lcm(19,38,57) = 114`. Each occurrence pair is retained once, including overlapping pairs. The fixed score is the lexicographic pair

```
(maximum qualifying maximal-repeat length, number of qualifying maximal-repeat pair regions).
```

The completed result will retain all witnesses, every column order, each transformed-stream SHA-256, the complete score distribution, and the strict-better count, tie count, and tied rank of `ZOMBIES`.

## Synthetic controls

`controls.py` compares the production seed-indexed repeat finder with an independently written all-position-pairs extender on all 4,095 binary strings of lengths 0 through 11. Dedicated fixtures cover nested repeats, overlapping repeats, a repeat ending at the input boundary, no repeats, and three planted occurrences at positions 0, 114, and 228. The latter must retain all three occurrence pairs with gaps 114, 228, and 114.

For geometry, the controls enumerate all 5,040 orders on a deterministic 1,092-symbol synthetic stream. For every order they compare production decode with an independent source-index gather, prove the indices are a permutation of 0 through 1,091, and check both encode/decode inverse directions. A separate labelled two-row construction checks the column-chunk convention.

Run the read-only controls and inert target preflight with:

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44_keyorder_census/controls.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44_keyorder_census/run_target.py
```

The only target command is:

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44_keyorder_census/run_target.py --run-target
```

It refuses an existing result or temporary file. Without that flag, it does not open the canonical MDX or dataset while no result exists. Once a result exists, default mode reconstructs all 5,040 rows from the pinned canonical sources and requires byte-for-byte semantic equality.

## Frozen preparation hashes

- `model.py`: `e7ef87e8cda01a75b45fd0f834f5b785338724dc326a7256e52018704ee37fb9`
- `controls.py`: `bed12a5728819bbe54ef9c9692f138ae2d05dd8a0a5766479764818c6d79a36d`
- `controls.json`: `6f4846ef1c5058e8e5f28e91671833a475cc6cef4647d33fac8fe1dcabe40ff9`
- `run_target.py`: `917fccd6688eaa380783088dd9131bcb924a2c0fe756e4272105174349579168`

The driver also pins the canonical MDX, dataset, and normalized input hashes. `controls.json` records only synthetic data.

## Limits

This census is an exact conditional comparison across column orders. It supplies neither the unknown outside program's `Z` statistic nor a random-null/global p-value. The chosen cut, direction, orientation, periods, minimum length, and key arose after broader exploration, so even an unusual tied rank is descriptive. The experiment does not test a cipher, recover plaintext, or establish a key length.

# Provisional exact occupancy screen

```json
{"identity":"ASTRA","status":"synthetic controls complete","target_evaluated":false}
```

This package derives a threshold for every byte length `n=128..1092` from the published exact occupancy recurrence

```
C[n,k] = k C[n-1,k] + (256-k+1) C[n-1,k-1].
```

For each length, `threshold_table.json` retains the largest integer `d` satisfying

```
P(D <= d) <= 10^-15
```

by the exact integer comparison

```
sum(C[n,0..d]) * 10^15 <= 256^n.
```

The generator also proves that `d+1` fails the inequality. Each compact row retains `n`, `d`, `d+1`, high-precision decimal and base-10-log tails, and SHA-256 hashes of both exact integer tail numerators. Default verification recomputes every integer distribution and comparison from the pinned published recurrence source.

Representative thresholds are:

| Length | Largest flagging `d` | `P(D<=d)` | `P(D<=d+1)` |
|---:|---:|---:|---:|
| 128 | 69 | `2.353686087572361e-16` | `1.899085970096456e-15` |
| 256 | 121 | `2.071590696878987e-16` | `1.086170966852318e-15` |
| 546 | 188 | `9.355541018644842e-16` | `4.734511189199835e-15` |
| 1092 | 231 | `7.775437473862881e-16` | `8.939151940878567e-15` |

## Standalone scorer

`score.js` uses only the Node.js standard library. It validates that all 965 table lengths are present, counts distinct byte values, and returns:

- `short`, with `screen_hit: null`, for `n<=127`;
- `out-of-range`, with `screen_hit: null`, for `n>=1093`;
- `flagged`, with `screen_hit: true`, for a covered length with `D<=d`;
- `unflagged`, with `screen_hit: false`, for a covered length with `D>d`.

A `flagged` output is retained for inspection; it is not discarded and is not a mathematical cipher exclusion. `Unflagged` is not evidence of meaningful plaintext. Short and out-of-range outputs were not tested by this screen and therefore have a null `screen_hit`. The scorer tests only occupancy and never guesses ASCII, Base64, letter, UTF-8, or other encoding membership.

Its batch input is a JSON array of `{id,hex}` records:

```sh
node research/rev7-20260909-codex/coverage/occupancy_screen_controls/score.js \
  --table research/rev7-20260909-codex/coverage/occupancy_screen_controls/threshold_table.json \
  --batch /path/to/input.json
```

## Controls and reproduction

The 28 synthetic scorer cases cover lengths 0, 127, 128, 129, 256, 546, 1091, 1092, and 1093. At six covered lengths they construct outputs with exactly `d-1`, `d`, and `d+1` distinct values. A deterministic 546-byte plant uses forty byte values `80..A7`, all outside ASCII, letters, and Base64; arbitrary position shuffling and reversal preserve both `D` and status. Separate fixtures use the literal 65-byte Base64 alphabet and the 52 ASCII letters. A full byte-label bijection `f(x)=(73x+41) mod 256` maps all 256 labels one-to-one and preserves `D` and status on an unflagged boundary fixture. An independently written Python reference counts each fixture and agrees exactly with JavaScript. A malformed table-profile fixture is rejected; the loader requires 256 labels, lengths 128 through 1,092, threshold `1/10^15`, all 965 rows, and `0<=d<=min(n,256)`.

Default checks are read-only:

```sh
python3 -B research/rev7-20260909-codex/coverage/occupancy_screen_controls/build_table.py
python3 -B research/rev7-20260909-codex/coverage/occupancy_screen_controls/controls.py
```

Explicit generation requires a new destination and refuses overwrite:

```sh
python3 -B research/rev7-20260909-codex/coverage/occupancy_screen_controls/build_table.py --generate /tmp/new-threshold-table.json
python3 -B research/rev7-20260909-codex/coverage/occupancy_screen_controls/controls.py --generate /tmp/new-controls.json
```

The recorded local validation used Python 3.9.6 and Node.js v26.4.0. The artifacts have no third-party runtime dependency.

## Scope and limits

The threshold is a provisional conservative **per-output** rule under independent uniform labelled bytes. No concrete candidate grid, actual comparison count, dependence structure, or cipher-output null has been registered. Consequently `10^-15` is not yet a family-wise probability or an empirical false-positive rate. The package reads no Rev7 data, evaluates no target output, and makes no claim about encoding membership, plaintext, or cipher correctness.

## Hashes

- Published occupancy source: `2506d407801a6f581ecfe01b91d71bf6e9a4a0524104ec582f5ef22cb2df3cd9`
- `build_table.py`: `1a45f4f32fca74ced1bf440a862a3c66795234486310f152c1275b3ff61bc41b`
- `threshold_table.json`: `2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447`
- `score.js`: `6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27`
- `controls.py`: `1db544a213716870b359001a47b0bce9c151734e45a10d9e254b917d4809e262`
- `controls.json`: `54f5861811e5b91db0341593cbe9486dc74251ec7280dd971cf7b3f55d9caf8c`

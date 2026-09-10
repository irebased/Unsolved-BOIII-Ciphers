# Exact cut-4 column-order census result

```json
{"identity":"ASTRA","status":"complete","target_evaluated":true}
```

The preregistered census completed once. It examined every one of the `7! = 5,040` read-column permutations for the fixed conventional decode of the canonical forward 1,092-symbol input as 273 indivisible four-symbol cells in a `39 × 7` rectangle.

For each transformed stream, the census retained every left- and right-maximal repeated occurrence-pair region of length at least four whose gap is divisible by `114 = lcm(19,38,57)`. The fixed ordering statistic was

```
(maximum qualifying maximal-repeat length, qualifying maximal-repeat pair-region count)
```

compared lexicographically with larger values first.

## Exact distribution

| Score | Column orders |
|---|---:|
| `(0,0)` | 4,125 |
| `(4,1)` | 176 |
| `(4,2)` | 9 |
| `(5,1)` | 535 |
| `(5,2)` | 51 |
| `(6,1)` | 135 |
| `(6,2)` | 9 |
| **Total** | **5,040** |

The `ZOMBIES` order `[3,5,4,2,1,6,0]` scored `(5,1)`. Exactly 195 orders scored strictly higher and 535 orders, including `ZOMBIES`, had the same score. Its rank with ties is therefore 196, and the tied block occupies ranks 196 through 730.

Its sole qualifying witness is `030E6` at zero-based starts 828 and 942, length 5 and gap 114. The complete transformed stream has SHA-256 `1cb32555f497309352adec7f5757bc3e9f5fb02fe077995ae0b83ff3a052d1be`.

## Execution and artifacts

The one authorized invocation was:

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44_keyorder_census/run_target.py --run-target
```

It exited successfully in the initial tool process after 2.941927459 seconds. No restart or resume occurred. The driver retained all 5,040 ordered rows, stream hashes, scores, and qualifying witnesses.

- Result: `target_results.json`, 1,872,997 bytes, SHA-256 `6edb51727cef5eac35d225827877bf9df7c2f3724109459b8024c36eba8bf36a`
- Model: `e7ef87e8cda01a75b45fd0f834f5b785338724dc326a7256e52018704ee37fb9`
- Controls: `bed12a5728819bbe54ef9c9692f138ae2d05dd8a0a5766479764818c6d79a36d`
- Control ledger: `6f4846ef1c5058e8e5f28e91671833a475cc6cef4647d33fac8fe1dcabe40ff9`
- Driver: `917fccd6688eaa380783088dd9131bcb924a2c0fe756e4272105174349579168`
- Preparation README: `459a736efe45b044b106c10198292f6945bc555f6b9fd32567af16c98755656d`
- Preregistration: FABLE message 490, before execution.

The independent diagonal verifier is maintained separately and was not invoked by this run owner, as requested.

## Interpretation and limits

This is an exact **conditional** comparison across column orders for one fixed cut, direction, orientation, period triple, repeat threshold, and scoring rule. The observation is shared by hundreds of column orders and is not uniquely associated with `ZOMBIES` within this census.

The census is not the outside program's unknown Gaussian-style `Z` calculation and supplies no global significance value or random-null probability. The fixed geometry and statistic were selected after broader exploration, so the tied rank does not correct selection across cuts, directions, orientations, periods, keys, or scoring definitions. It does not establish a key length, identify a cipher, recover plaintext, or exclude other hypotheses.

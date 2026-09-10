# Geometry order-cost audit

<!-- identity: ASTRA -->

Planning-model audit only. It uses `q=105/256` as an independent-uniform relaxed-byte assumption; values are neither probability evidence nor runtime guarantees. No crypto, key, IV, or plaintext evaluation was performed.

| Orientation | Anchor | Optimal remaining order | Model cost | Solver greedy cost | Ratio | DP states |
|---|---|---|---:|---:|---:|---:|
| byte_reverse | 24789CD | 6,0,3,E,5,F,1,A,B | 2706081240.100 | 2706081240.100 | 1.000000 | 512 |
| forward | 24789CD | 6,0,3,E,5,F,1,A,B | 2706081240.100 | 2706081240.100 | 1.000000 | 512 |
| nibble_swap | 24789CD | 6,0,3,E,5,F,1,A,B | 2706081240.100 | 2706081240.100 | 1.000000 | 512 |
| reverse | 24789CD | 6,0,3,E,5,F,1,A,B | 2706081240.100 | 2706081240.100 | 1.000000 | 512 |

All four orientations have the same geometry-derived order and cost. The source evaluates all 512 dynamic-programming states per orientation. The JSON records the visited-state count, selected-order B-counts, anchor cost, greedy comparison, and brute-force cross-check; it does not include the complete DP state table. The solver greedy remaining order is reproduced from `solver.py:_order` tie rules using true displayed-character frequency from the hash-pinned canonical MDX, without constructing DES or evaluating keys. The forward orientation also cross-checks the DP against all 9! = 362,880 remaining-symbol orders; the other orientations use the complete 512-state DP only.

The full geometry ledger is regenerated with `python3 research/rev7-20260909-codex/iv_independent/geometry.py`; this audit is structural only.

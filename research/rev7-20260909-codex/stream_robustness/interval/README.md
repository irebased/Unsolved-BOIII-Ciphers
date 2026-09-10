# Contiguous-interval feasibility solver

This package asks a synthetic arithmetic question: what is the shortest half-open byte interval `[start,end)` that can be ignored so every displayed pair class has at least one fixed mapped byte satisfying all constraints outside the interval?

For pair class `p`, candidate ciphertext byte `c` is allowed outside the interval exactly when every outside occurrence `i` satisfies:

```text
c XOR keystream[i] in allowed_plain_bytes
```

The implementation starts with every position outside the window. It stores, for every pair class and candidate byte, the number of outside positions that reject that candidate. A candidate is feasible exactly when its count is zero. Expanding the erased window only removes constraints, so feasibility is monotone. The right endpoint advances at most `n` times; the left endpoint also advances at most `n` times. Each position update touches `q` candidates.

- Feasibility core: `O(n*q)`; for byte mappings, `q=256`.
- Witness materialization: up to `O(n*k*q)` because each provisional or tied minimum may scan all `k` class rows.
- Counter space: `O(k*q)`, where `k` is the number of pair classes.
- Retained witness space: `O(m*k)` for `m` minimizing intervals.
- Output: every shortest interval, with one independently checkable arbitrary-map witness per interval.
- Coordinates: the supplied oriented decoded-byte sequence only.

The controls use no cryptography and do not read Rev7. An independent oracle enumerates every interval and reconstructs candidate intersections from scratch. It is compared against the two-pointer solver on explicit zero-length, full-erasure, multiple-minimum, repeated-class, singleton-class, and boundary fixtures; exhaustive small inputs; and fixed-seed random inputs.

Run:

```text
python3 -B research/rev7-20260909-codex/stream_robustness/interval/controls.py
```

A prospective target result would be a lower bound on the byte span of one contiguous corruption region under an arbitrary fixed displayed-pair mapping and a specified stream/alphabet. It would not recover corrected bytes, require injectivity, or cover multiple disjoint regions.

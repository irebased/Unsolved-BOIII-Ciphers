# The repeated string behind the 19/38/57 supports

Identity: ASTRA. This reproduces a plausible support-count definition, not the outside program's unknown Z score.

Conventional AMSCO decoding with equal four-character cuts and column key ZOMBIES produces `030E6` at zero-based positions 828 and 942. Both occurrences are left- and right-maximal: their preceding and following symbols differ. The spacing is 114.

| Counted substring | Occurrence positions | Gap |
|---|---|---:|
| `030E` | 828, 942 | 114 |
| `30E6` | 829, 943 | 114 |
| `030E6` | 828, 942 | 114 |

Since 114 = 6×19 = 3×38 = 2×57, all three rows support all three periods. Counting repeated n-grams of lengths four through eight gives exactly 3/3/3; merging these nested substrings gives one repeated region. The apparent harmonic pattern therefore does not supply three independent repetitions or establish a key length.

The independent replay derives every output position directly from column ranks, without importing the geometry module. It verifies the complete transformed-stream SHA-256 and every literal repeat above, checks maximality, and enumerates all repeated 4–8-grams.

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44/independent_witness.py
```

The source is pinned to the canonical repository dataset. Its output is retained in independent_witness.json. REPORT.md records the separate four-context analysis and all aggregation alternatives. No outside-program identity, Z formula, null distribution, or plaintext has been established.

score_illustration.py is a separate hypothetical statistical example. It shows that standardizing a small Poisson count can give a numerical Z near six while its exact count-tail probability differs greatly from a Gaussian tail. It is not a calibration of the supplied scores and reads no Rev7 data.

# ASTRA byte-pair repetition audit

This source-only statistic computes equality and repetition counts for the pinned 546-byte Rev7 stream (the `83 B57B2...` ciphertext). It performs no deciphering, key evaluation, or search. The source independently extracts the ciphertext from both the canonical MDX and the dataset record, asserting both file hashes and the canonical 1,092-hex hash.

All four orientations (`forward`, `full_hex_reverse`, `byte_reverse`, `nibble_swap`) have 226 distinct byte values, 30 unobserved values, 63 singleton values, 67 doubletons, 320 repeated occurrences, 564 unordered equal-position pairs, 2 adjacent equalities, and maximum run 2. Multiplicity histogram is `{1: 63, 2: 67, 3: 56, 4: 24, 5: 11, 6: 5}`. The full lag histogram for lags 1..545 is in `repeats.json`; normalized first-occurrence patterns verify orientation equivalence under relabeling and/or position reversal.

Default verification recomputes statistics and compares the existing ledger without rewriting it. Regeneration requires a new output path:

```sh
python3 research/rev7-20260909-codex/homophonic/repeats/repeats.py --regenerate /tmp/repeats-new.json
python3 research/rev7-20260909-codex/homophonic/repeats/repeats.py
```

Identity: ASTRA.

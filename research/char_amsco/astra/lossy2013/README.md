# Lossy CrypTool AMSCO keys 2013 and 2014

Identity: **ASTRA**

This synthetic-only package models the original CrypTool character AMSCO row-label behavior for literal numeric keys `2013` and `2014`. Both keys emit the same natural input positions. In each complete six-hex-character row they retain positions 0, 1, 3, 4, and 5, yielding natural ciphertext-byte masks `FF,0F,FF`.

`core.py` derives the emission indices for arbitrary input length and handles partial final rows. `controls.py` compares those indices with the pinned source port in `../cryptool_bug/analyze.py` for every input length 0 through 300 and seven longer fixtures, for both keys.

For an observed output length of 1092 hex characters, the row formula is

```
M(n) = 5 * floor(n / 6) + [0,1,2,2,3,4][n mod 6].
```

Since the remainder contribution is between 0 and 4, the equation M(n)=1092 forces q=floor(n/6)=218. The remaining contribution must be 2, which occurs only for remainders 2 and 3. Thus the only natural lengths over the unbounded nonnegative domain are 1310 and 1311 hex characters; requiring a complete byte string leaves exactly 1310 hex characters, or 655 bytes.

The fixed-IV frontier accepts printable ASCII bytes 32 through 126. It retains every compatible path and uses no score or language pruning. The only bounds are 100,000 live frontier states and 5,000,000 cumulative accepted states. Reaching either cap is explicitly `INCOMPLETE`.

Reproduce the ledger read-only:

```sh
python3 -B research/char_amsco/astra/lossy2013/controls.py
```

Regenerate to a new path:

```sh
python3 -B research/char_amsco/astra/lossy2013/controls.py --regenerate /tmp/lossy2013-controls.json
```

Requires Python 3.9-compatible syntax and PyCryptodome. No Rev7 ciphertext is read, and there is no target driver.

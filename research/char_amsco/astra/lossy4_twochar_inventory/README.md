# Four-digit four-character-row inventory

Identity: **ASTRA**

This source-only package classifies every positive decimal four-digit key from `1000` through `9999` under the pinned original CrypTool source21 AMSCO assignment. It selects only keys whose complete six-character row emits exactly four characters.

The independent index model preserves complete source cells and applies the same last-assignment-wins row labels. It separately constructs partial rows, where an absent later duplicate may expose an earlier cell.

For an observed length of 1,092, the all-length proof uses

```
M = 4q + t(r),  q = floor(N/6),  0 <= t(r) <= 5.
```

This forces `q` to 272 or 273. Requiring even natural input length leaves only remainders 0, 2, and 4, hence six candidate lengths: 1,632, 1,634, 1,636, 1,638, 1,640, and 1,642. Exact partial-row maps decide all six.

The ledger retains all 864 qualifying key IDs and their source geometry. Exact emission-map classes retain their complete 1,092 source indices, hashes, representatives, and members. It also records the first-eight-byte ciphertext masks and the corresponding unconstrained unknown-nibble root-domain counts without enumerating those roots.

Read-only full verification:

```sh
python3 -B research/char_amsco/astra/lossy4_twochar_inventory/inventory.py
```

Regenerate only to a new path:

```sh
python3 -B research/char_amsco/astra/lossy4_twochar_inventory/inventory.py --regenerate /tmp/lossy4-twochar-inventory.json
```

No Rev7 content, cryptography, plaintext testing, or target search is performed. The map classes apply only to the 864 qualifying keys, not all 9,000 four-digit keys.

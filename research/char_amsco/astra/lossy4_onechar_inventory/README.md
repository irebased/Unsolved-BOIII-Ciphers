# Positive four-digit one-character-loss inventory

Identity: **ASTRA**

This source-only inventory enumerates every positive four-digit decimal key from `1000` through `9999` under the pinned original CrypTool source21 AMSCO encoder. It selects only keys that emit five characters from each complete six-character row.

The original assignment at `class.amsco.php:191` stores the complete cell value in one row/label slot:

```php
$out[$row][$str_key[$col-1]] = $value;
```

A later column with the same label replaces that entire value. The control `ABCDEF` with key `1123` emits `CDEF`: the later one-character cell `C` replaces the complete two-character cell `AB`. There is no character-by-character trimming within a cell. Partial final rows are constructed and classified separately because an absent later duplicate can expose an earlier cell.

For each key the ledger retains its full-row emission count and qualification status. Every qualifying key also records retained columns, zero-based dropped column, read order, compatible even natural lengths, and membership in an exact full emission-index-map class. Each class contains its full index map, map hash, representative, and complete member list.

Default read-only verification recomputes all 9,000 classifications and source comparisons:

```sh
python3 -B research/char_amsco/astra/lossy4_onechar_inventory/inventory.py
```

Regenerate only to a new path:

```sh
python3 -B research/char_amsco/astra/lossy4_onechar_inventory/inventory.py --regenerate /tmp/lossy4-inventory.json
```

No Rev7 content or cryptography is read or evaluated. This covers only positive four-digit keys with one character lost per complete row; it is not an inventory of every malformed numeric key.

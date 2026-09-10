# Lossy CrypTool AMSCO `2016` masked-CFB8 controls (ASTRA)

The legacy character-level AMSCO assignment for literal key `2016` keeps natural nibble positions 0, 1, 3, and 4 in each six-nibble row. It emits position pair 3–4 for every row, then pair 0–1 for every row. Replacing the values at their natural locations gives repeating ciphertext-byte masks `FF,0F,F0`. `controls.py` requires this direct oracle to equal the hash-pinned `cryptool_bug/analyze.py` source port at 3, 6, 99, and 819 bytes. PHP is not executed.

For a fixed CFB8 key and IV, each state retains the complete feedback register, plaintext prefix, and ciphertext prefix. The next ECB byte fixes the relation `C=P xor E(register)[0]`; all 27 allowed plaintext bytes are tested against the observed mask. No beam score or other pruning is used. Every path is retained. A simultaneous frontier cap of 100,000 and cumulative accepted-state cap of 5,000,000 are safety limits; hitting either makes that case explicitly incomplete.

Controls encrypt new uppercase-English plants of 99 and 819 bytes with DES and AES-128 under NUL and ASCII-zero IVs. PyCryptodome CFB8 is checked against the manual recurrence. The exact planted plaintext/ciphertext pair and every additional solution are retained. Four deterministic random masked streams use the same 1,092-character observed length. A separately labeled DES/NUL 99-byte calibration reuses the exact plant mask with the 53-byte alphabet A-Z, a-z, and SPACE; it hits the 100,000-frontier cap and is reported incomplete, without an exclusion claim. The estimate `27^3/65536 = 0.3003` is a heuristic average only.

```sh
python3 -B research/char_amsco/astra/lossy2016/controls.py
python3 -B research/char_amsco/astra/lossy2016/controls.py --regenerate /tmp/lossy2016-controls.json
```

No Rev7 data is read and no target driver exists.

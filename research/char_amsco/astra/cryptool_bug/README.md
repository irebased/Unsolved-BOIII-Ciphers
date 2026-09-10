# CrypTool legacy AMSCO key-validation bug (ASTRA)

The original CrypTool implementation has a concrete lossy-encryption bug for malformed numeric keys. The frontend converts every numeric submission to an integer but checks only that it is an integer. It does not enforce the UI's stated rule that the key contain every consecutive rank exactly once. During encryption, `sortArray()` assigns each natural column cell to an array entry named by one key character. A repeated label overwrites the earlier cell in the same row. Encryption then reads only labels `1..strlen(key)`, so label zero and out-of-range labels disappear.

Minimal examples, before the tool's five-character presentation grouping:

- key `12`, plaintext `ABC` -> `ABC`, and key `21` -> `CAB`; both decode to `ABC`;
- key `11`, plaintext `ABC` -> `C`: the second column overwrites `AB`; malformed-key decode is empty (`ABCDE` separately gives `CDE` then decodes only to `E`);
- keys `10` and `13`, plaintext `ABC` -> `AB`: label 0 or 3 lies outside the emitted range 1..2, so `C` is deleted and malformed-key decode is empty;
- submitted key `012` becomes integer/effective key `12`, silently changing the intended width from 3 to 2;
- at the class level, width-10 key `1234567890` with plaintext `ABCDEFGHIJKLMNO` emits only `ABCDEFGHIJKLMN`: rank 10 cannot equal any single key character, label 0 is omitted, and malformed decode yields `CDEFGHIJKLMN`.

The partial-row behavior is row-local. With key `121` and plaintext `ABCDEFGH`, full-row rank 1 keeps the later duplicate column (`DE`), while the partial final row lacks that later column and keeps the earlier one (`F`). The result is `DEFCGH`, losing `AB`. Thus malformed repeated labels do not always select one fixed natural column across the entire message.

This is primarily an encryption/generation defect: a historical malformed key could create a shorter, noninvertible ciphertext. Decryption also fails to invert such output because deleted bytes are absent, duplicate ranks address only the first occurrence, and a missing rank falls through to the first natural column under the historical null arithmetic. No inverse column permutation can restore the erased data.

For valid keys, the bug is absent. The harness structurally enumerates all 409,112 permutations at widths 2 through 9 and compares representative 1,092-character outputs directly with ASTRA's accepted generic character AMSCO model. The original starts `2,1` only: at the first cell, `1 + (1 % 2) = 2`. The generic model matches when configured with start `21`. Width 10 is outside the original one-character-rank key representation because `getPos(10)` compares rank 10 against one character at a time; the adjacent characters `1`,`0` are never one rank 10. Frontend integer range for ten-digit inputs is also platform-dependent, so the width-10 witness is explicitly class-level.

The original operates on PHP string bytes. For uppercase hex this means 1,092 character units, versus 546 units in the separate byte-AMSCO analogue. At 1,092 characters the `2,1` sequence has 728 cells and no truncated cell; widths 2, 4, 7, and 8 have complete final rows, while widths 3, 5, 6, and 9 are partial. Per-character `trim()` also removes whitespace and NUL before transposition; it does not alter whitespace-free uppercase hexadecimal.

Source: `cryptool-org/cto` commit `4fc443f0d87c0e86815695a47ab2d6174c725f82`, added as legacy tools on 2016-08-12. The decisive assignment is [class.amsco.php line 191](https://github.com/cryptool-org/cto/blob/4fc443f0d87c0e86815695a47ab2d6174c725f82/_ctoLegacy/tools/amsco/class.amsco.php#L191); emission is lines 100–103. Frontend integer conversion and the insufficient guard are `default_tool.php` lines 35 and 46. Exact source snapshots and hashes are included here.


## Source transport

The original `class.amsco.php` is a 5,730-byte Latin-1 file (SHA-256 `132d61ff8b794ab9717a0ce284d7bf21f82c8dbfe39bf9f1a3b5f7aa7eb91e4f`). GitHub connector transport requires UTF-8 content, so publication uses the canonical line-wrapped `source/class.amsco.php.base64` (7,641 bytes, SHA-256 `25143ebd1a720d9fe35ac3aa2579be722a8ded03b67d6ff2da0f071e40f8c3ac`). The verifier decodes this representation in memory only when the raw file is absent, then checks the exact raw length and hash. The original raw file remains local and unchanged.

A reader may reconstruct the raw file in a checkout where it is absent:

```sh
python3 -c 'import base64,pathlib; q=pathlib.Path("research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64"); p=q.with_suffix(""); p.write_bytes(base64.b64decode(b"".join(q.read_bytes().split()), validate=True))'
```

PHP was not available in the audit environment and was not installed or executed. The reproducer is a source-backed Python port of the cited assignment, emission, preprocessing, frontend-cast, and decode loops; root also confirmed the minimal cases with an independent short port.

Read-only verification recomputes every witness:

```sh
python3 -S -B research/char_amsco/astra/cryptool_bug/analyze.py
```

Regeneration refuses an existing path:

```sh
python3 -S -B research/char_amsco/astra/cryptool_bug/analyze.py --regenerate /tmp/cryptool-amsco-bug.json
```

This evidence does not show that Rev7 used an invalid key or CrypTool AMSCO. It identifies a historically possible generation path that ideal bijective AMSCO searches intentionally exclude. No target data or cryptography is evaluated.

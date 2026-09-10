# Extended ellipsis witness regeneration

<!-- identity: ASTRA -->

This bounded check reconstructed target streams and hash-matched every generated stream to its frozen target cell before arithmetic testing. It checks all **92 fixed-byte witnesses** with expanded relaxed alphabet (104 + `0xA6` = 105), trying all occurrences of the recorded pair and all other repeated displayed pairs. **20 old minimal witnesses lose their contradiction** after expansion, but all 92 have regenerated contradictory repeated-pair witnesses; `unresolved_after_regeneration_count` is 0. Each row stores one representative contradiction and its total count in `extended_result.json`. No plaintext is inferred.

The four separate Blowfish/NUL constant-stream records retain 226 distinct displayed bytes in each orientation, exceeding 105, so the bijection-count contradiction remains arithmetic.

Standard AES/DES/Blowfish streams were reconstructed with PyCryptodome ECB OFB8/fullblock recurrence. Blowfish-compat was also recomputed using the previously verified compatibility block helper; all stream SHA-256 values were matched before witness evaluation. Rows mark `crypto_recomputed: true`; compatibility rows mark `independent_cipher_implementation: false` because that helper is reused.

Run: `python3 research/rev7-20260909-codex/sources/ellipsis_witness/extend.py`

Input hashes, dependency hashes, complete contextual identifiers, and stream-match assertions are embedded in `extended_result.json`.

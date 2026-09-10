# Lossy-2013 synthetic control report

Identity: **ASTRA**

The source-derived geometry checks pass. Across 616 key/length comparisons, the independent emission-index implementation exactly equals the pinned original-source port. Literal keys `2013` and `2014` emit identically. Complete rows retain hex positions 0, 1, 3, 4, and 5, corresponding to byte masks `FF,0F,FF`. The 655-byte case ends with one additional `FF` byte after 218 full mask cycles.

The quotient/remainder equation proves the length result without a bounded scan: a 1092-character output forces q=218 and remainder contribution 2, hence natural lengths 1310 or 1311 only. Exactly one is even: **1310 hex characters, or 655 bytes**.

All four registered printable-ASCII plants complete below the caps:

| Plant | Complete solutions | Accepted states | Block calls |
|---|---:|---:|---:|
| 99 bytes, DES, NUL IV | 8 | 1,012 | 1,005 |
| 99 bytes, AES-128, ASCII-0 IV | 6 | 972 | 967 |
| 655 bytes, DES, NUL IV | 7 | 10,966 | 10,960 |
| 655 bytes, AES-128, ASCII-0 IV | 3 | 7,489 | 7,487 |

The exact planted path is present in every plant result. Every retained solution includes its complete plaintext and ciphertext bytes and passes independent PyCryptodome CFB8 re-encryption, manual decryption, the generic emission map, and the pinned legacy source emission.

Two deterministic random 1092-character observations, one per backend, both exhaust completely with zero paths after four natural bytes. These are synthetic null controls, not evidence about Rev7. Two three-byte controls complete with two and three solutions and exercise exhaustive retained-solution validation.

The search alphabet is exactly printable ASCII 32 through 126. Results say nothing about larger byte alphabets, unknown keys or IVs, other ciphers, other malformed AMSCO keys, or any target ciphertext. A capped run would be incomplete, though none of the recorded controls reached a cap.

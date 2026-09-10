# Nibble-additive periodic controls

Identity: **ASTRA**. This target-free package models independent arithmetic on the two hexadecimal digits of each byte. For subtraction, plaintext nibbles are `(C-K) mod 16`; for Beaufort they are `(K-C) mod 16`.

For a hexadecimal key period `m`, pairing successive key nibbles produces a byte-key sequence of period `m/gcd(m,2)`. If `m` is odd, paired keys repeat after `m` bytes but adjacent residue keys share underlying nibble variables. Ignoring those equalities and intersecting 256 arbitrary paired-key values independently is a necessary-condition relaxation: an empty relaxed residue still excludes every consistent nibble key, while a nonempty result remains unresolved.

The controls exhaust all 256 ciphertext bytes by all 256 paired keys for both operations. Six plants cover hexadecimal periods 19, 38, and 57 and both operations. Each 546-byte UTF-8 plant contains every one of the 201 allowed codepoints, is encrypted nibblewise, encoded using the fixed equal-cut-4 `ZOMBIES` geometry, restored exactly, and checked with fast intersections and an explicit slow enumeration.

No Rev7 ciphertext or dataset is read. This does not cover nibble-additive variants beyond the declared geometry, periods, or operations.

Run: `python3 -B controls.py`.

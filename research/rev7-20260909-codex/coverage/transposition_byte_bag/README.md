# Byte-bag invariance and CFB8 one-edit bounds

Identity: **ASTRA**

This synthetic proof uses exactly the declared endpoint codepoints: TAB, LF, CR; U+0020 through U+007E; U+00A0 through U+00FF; and U+2013, U+2014, U+2018, U+2019, U+201C, U+201D, U+2026. It does not substitute all Unicode.

Their UTF-8 codewords comprise 98 one-byte, 96 two-byte, and seven three-byte words. Their union contains 165 distinct byte values:

- the 98 allowed single-byte values;
- all 64 continuation bytes 80 through BF;
- lead bytes C2, C3, and E2.

Any byte transposition preserves this byte histogram, so membership in the 165-byte union is a necessary invariant. UTF-8 validity, allowed-codepoint counts, and longest allowed-codeword runs are not byte-bag invariants.

The package also proves the distinct local statement for one ciphertext edit in CFB8 with block size `b`. A substitution affects at most `b+1` output positions. An insertion affects at most `b` aligned original positions plus one extra output. A deletion affects at most `b` aligned original outputs plus one lost original position. These bounds assume the correct cipher, key, CFB8 convention, alignment outside the edit, and only that each undamaged plaintext byte belongs to the 165-byte union. Ordered UTF-8 is not required, so any plaintext byte permutation of a valid declared-endpoint encoding is covered. A decoder IV may be arbitrary: after the first `b` damaged ciphertext bytes, the CFB8 register contains only ciphertext and is IV-independent. A transposition applied to ciphertext itself is not one edit and is outside this theorem.

Run the full read-only replay:

```sh
python3 -B research/rev7-20260909-codex/coverage/transposition_byte_bag/proof.py
```

Regenerate only to a new path:

```sh
python3 -B research/rev7-20260909-codex/coverage/transposition_byte_bag/proof.py --regenerate /tmp/transposition-byte-bag.json
```

Requires PyCryptodome for synthetic DES-CFB8 controls. No Rev7 bytes are read and no target or FABLE scoring lane is executed.

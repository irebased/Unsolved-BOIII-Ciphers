# Periodic repeating-key byte-bag controls

Identity: ASTRA. Target evaluated: false. No Rev7 source, transcription, or result is read by this package.

## Exact necessary condition

The endpoint contains exactly 201 literal codewords:

- TAB, LF, and CR;
- U+0020 through U+007E;
- U+00A0 through U+00FF;
- U+2013, U+2014, U+2018, U+2019, U+201C, U+201D, and U+2026.

Encoding those codepoints as UTF-8 produces a union of exactly 165 byte values: the 98 permitted single-byte ASCII/control values, all 64 continuation bytes 80 through BF, lead bytes C2 and C3, and lead byte E2. model.py defines the literal codepoint tuple and derives every codeword and union byte from it. controls.json records all codepoints, codeword hex strings, byte values, and source hashes.

For a candidate repeating-key period q and residue r, every ciphertext position i congruent to r uses the same key byte k. The XOR model requires x XOR k to belong to the 165-byte bag. The subtraction model requires (x - k) modulo 256 to belong to the bag. Each observation gives a 256-bit candidate-key mask; intersection over a residue gives all key bytes satisfying the byte-bag condition for that residue.

If any residue mask is empty, no period-q key can satisfy this endpoint byte bag. A nonempty mask is only necessary. It does not prove ordered UTF-8 validity, codeword boundaries, language, or a plaintext recovery. The masks do not impose injectivity or a global ciphertext-byte-to-plaintext-byte map.

The fast implementation builds and intersects 256-bit integer masks. An independently written slow reference tests every key value from 0 through 255 against every byte in a residue.

## Synthetic controls

A deterministic 546-byte mixed ASCII and Unicode plaintext is encrypted under periods 1, 2, 3, 8, 31, and 64, for XOR and modular-add encryption corresponding to subtraction decryption. All four canonical hexadecimal orientations are inverted before mask evaluation, producing 48 complete cases. Every fast mask equals the slow reference, and every true residue key remains in its mask. The ledger retains all masks and candidate lists.

The controls also establish:

- empty input makes every residue vacuous with all 256 keys retained;
- observation order and duplicate observations within a residue do not alter its intersection;
- a residue containing bytes 0 through 255 has an empty mask for both operations;
- ciphertext ASCII AA under XOR key 0001 becomes hexadecimal 4140, or ASCII A@. Thus identical ciphertext bytes in different residues can validly map to different allowed plaintext bytes, refuting a global fixed-mapping distinct-count argument.

## Reproduce

Default read-only verification recomputes the complete fast and slow control grid:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/controls.py

Regeneration writes a new path and refuses overwrite:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/controls.py --regenerate /tmp/periodic_bytebag_controls.json

This package contains no target driver or gate. A future target scope requires separate review and registration.

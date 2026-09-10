# Scope review of the 544-byte padded-tail bound

Identity: **ASTRA**. This is a read-only source review. It performs no decryption or target sweep.

## Finding

The common-prefix length **544 is correct for 8-, 16-, and 32-byte blocks**. It is divisible by all three block sizes:

- 68 complete 8-byte blocks;
- 34 complete 16-byte blocks;
- 17 complete 32-byte blocks.

The frozen RA implementation (`mode.rs` SHA-256 `1bcd119703cccf4a644673bdeae0b503d2190a2dff10c072923fa0df57933495`, lines 135-156) decrypts every complete input block and copies the final two ciphertext bytes unchanged. The current `/private/tmp/ra-prefix-fix` implementation at clean commit `25958812bb28d610bbdb971a479bc99067b9c907` (`mode.rs` SHA-256 `e693fd73f682285cc29ceab4a496f77420882e744649efd2a13e1bf713acc353`, lines 241-260) appends NUL ciphertext bytes to a whole block and decrypts that final block.

For ECB, each plaintext block through offset 543 depends only on the identical ciphertext block. For CBC, each plaintext block through offset 543 depends on that identical ciphertext block and its identical predecessor (the IV only affects block zero). The newly padded block begins at offset 544 and cannot change an earlier plaintext block. Thus the first 544 decrypted bytes agree **provided the primitive, key derivation/key bytes, IV, mode, and original ciphertext bytes are identical**. This argument is block dependency, not an empirical assumption about the final block.

The new implementation changes more than the final two output bytes:

- ECB/CBC output length changes from 546 to 552, 560, or 576 for block sizes 8, 16, or 32.
- Bytes from offset 544 to the rounded end become a decrypted block rather than two passed-through ciphertext bytes.
- Consequently full-output hashes, distinct-byte counts, and any length-dependent score can change.
- The current source implements PHP-style zero-padding and rounded output without unpadding. Its comments separately describe the C-port rejection/unpadding convention and an unresolved possibility of application-layer NUL trimming. This review does not prove the historical site used either presentation convention.

Other feedback-mode branches are unchanged by the inspected ECB/CBC patch. This review does not compare changes elsewhere in the RA repository or assert that a future sweep retains the same Cartesian axes or applicability decisions.

## Exact saved-result scope

The published bound applies to **3,312 labels selected from the old frozen RA result**, not to an independently rerun current target set. They are the old `READY` rows satisfying all of:

- an actual block primitive (stream primitives are excluded even if a saved label says ECB/CBC);
- mode ECB or CBC;
- saved output/input length 546, which is nonaligned for its 8-, 16-, or 32-byte block size.

There are 1,656 ECB and 1,656 CBC labels. Their block-size counts are 2,016 at 8 bytes, 1,080 at 16 bytes, and 216 at 32 bytes. The saved result and selection certificate remain fixed; a changed future axis grid would require separate accounting.

## Length and occupancy bound

For each saved row, let `P` be its stored plaintext bytes `0..544` and `Q = P.rstrip(NUL)`. Under the identical-parameter dependency condition above, a PHP-padded decrypt is `P || T`, where `T` is the new final plaintext block suffix of length 8, 16, or 32. Without presentation trimming its length is exactly 552, 560, or 576. If a later display layer removes any number of trailing NUL bytes, the output still starts with `Q`; conservatively its length lies in `[len(Q), rounded_length]` and its distinct-byte count is at least `D(Q)`.

The saved rows have `len(Q)` 543 or 544 and `D(Q)` 209 through 239. Every integer candidate length is supported by the pinned occupancy table; the largest applicable threshold is 192. The minimum margin is 19. Therefore all 3,312 corresponding padded outputs remain unflagged even when the entire new final plaintext block is treated as arbitrary and optional trailing-NUL removal is allowed.

This proves a property of the corresponding saved parameter labels under the stated common-prefix model. It does not prove historical PHP/tool equivalence, determine the actual final block, or cover a different KDF, IV, primitive implementation, mode, ciphertext, axis grid, or scoring table.

## Reviewed artifacts

- Frozen old result SHA-256: `448ff7f95d9d07a334439ec4ddca831da5d15173bcba104858aed337f4cd67cb`
- Saved bound result SHA-256: `40db1f8ae0a80153ff0caa9808d2bf2a830eabed2de1b1700da82331b879259f`
- Bound model SHA-256: `0c830310ba3bdd823c0bc454153983d2c33a404ca28dec0286c0346da55a7081`
- Bound controls ledger SHA-256: `23606072cdaa3666b51dddc3f2d9d701a4b35c7d6874cdddea22648a2192b248`

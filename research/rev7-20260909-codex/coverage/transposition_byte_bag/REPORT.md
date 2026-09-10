# Transposition byte-bag proof result

Identity: **ASTRA**

The exact endpoint byte union has **165 values**, derived from 98 one-byte, 96 two-byte, and seven three-byte UTF-8 codewords. A byte permutation preserves that union and the full byte histogram. It does not guarantee any positive allowed-codeword run.

A valid-UTF-8 counterexample works at arbitrary length. Start with repeated U+2013, whose allowed encoding is `E2 80 93`. Within every three-byte group, permute the continuation bytes to `E2 93 80`, the valid UTF-8 encoding of U+24C0, which is outside the declared endpoint. The source and result have identical byte histograms. The original allowed run spans the entire input, while the permuted output has longest allowed-codeword run **zero**. Controls verify this at 3, 6, 48, and 768 bytes.

The separate CFB8 one-edit proof also passes. It requires only that every undamaged plaintext byte belongs to the 165-byte union; ordered UTF-8 is unnecessary. It therefore covers any byte permutation of a valid declared-endpoint encoding performed before CFB8 encryption. A changed ciphertext byte appears directly in its plaintext position and in at most the next `b` previous-ciphertext register windows. Insertion and deletion shift aligned windows for exactly the bounded resynchronization region described in the ledger.

Synthetic DES-CFB8 controls use a 311-byte plaintext containing every declared endpoint codeword. They exhaust all 311 substitution positions, 312 insertion boundaries, and 311 deletion positions. Manual register decryption equals PyCryptodome throughout. With `b=8`, observed maxima are:

| Damage | Maximum affected positions | Maximum present bytes outside union after initial block |
|---|---:|---:|
| substitution | 9 output positions | 8 |
| insertion | 8 aligned changes plus 1 extra | 7 |
| deletion | 8 aligned changes plus 1 lost original | 7 |

For deletion, the lost original position is not a present decoded byte; therefore present outside-union bytes are bounded by `b`, while the alignment edit count including the loss is bounded by `b+1`.

Two substitution fixtures, at ciphertext positions 3 and 10, also use an arbitrary wrong decoder IV. In both cases the wrong-IV and registered-IV damaged plaintexts are identical from byte 8 onward, and all later deviations from the undamaged plaintext lie inside the edit resynchronization window. This demonstrates that the decoder IV is flushed after the first `b` damaged ciphertext bytes.

These statements do not model a transposition applied to ciphertext as one edit, multiple corruptions, wrong keys, wrong modes, adaptive missing-ciphertext completion, or all Unicode. Arbitrary plaintext byte permutation before encryption is covered by the byte-membership premise. The controls are mathematical and synthetic; they do not rerun or grade FABLE outputs.

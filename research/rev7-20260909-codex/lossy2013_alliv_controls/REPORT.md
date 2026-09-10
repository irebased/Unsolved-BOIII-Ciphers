# Audit result: lossy `2013`/`2014` all-IV prototype

Identity: **ASTRA**

The corrected synthetic search is complete for both planted controls and the deterministic null. It enumerates all 4,096 observation-compatible initial ciphertext registers before applying the DES CFB8 printable-suffix constraint.

| Control | Natural bytes | Terminal solutions | Accepted suffix states | DES block calls | Maximum live frontier per root |
|---|---:|---:|---:|---:|---:|
| Original short plant | 99 | 68 | 32,285 | 36,313 | 48 |
| Original long plant | 655 | 280 | 391,435 | 395,251 | 284 |
| Deterministic null | 655 | 0 | 27,236 | 31,332 | 60 |

Each plant retained its exact full ciphertext and its exact plaintext suffix once. All terminal candidates passed independent library CFB8 suffix decryption, a separate manual register recurrence, exact `2013` and `2014` legacy emissions, length checks, printable-byte checks, and stored hashes.

The one-state cap control stops during root 2 at natural byte 8. It reports two completed roots, one partial root, 4,093 unexamined roots, one accepted state, and zero terminal solutions. This demonstrates that partial paths are not misclassified.

These controls establish the search mechanics only. They do not evaluate Rev7, infer the original IV, recover the first eight plaintext bytes, or classify printable output as meaningful language.

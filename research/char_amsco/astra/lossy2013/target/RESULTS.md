# Lossy-2013 fixed-IV target result

Identity: **ASTRA**

## Frozen scope

The registered grid contains one source-equivalent `2013`/`2014` emission model, four canonical observed-hex orientations, DES and AES-128, and NUL and ASCII-`0` IVs: **16 contexts**. Each context reconstructs 655 natural ciphertext bytes from the 1092 displayed hex characters and requires every plaintext byte to be printable ASCII 32 through 126.

Every compatible path is retained. There is no score or language pruning. The registered caps are 100,000 frontier states and 5,000,000 cumulative accepted states; a cap would mean `INCOMPLETE`.

## Result

All **16 contexts complete without reaching a cap and have zero compatible paths**. The independent verifier reconstructs the historical row-label emission indices and `FF,0F,FF` masks directly, then replays each first empty natural-byte prefix.

| Cipher | IV | Orientation | First empty after bytes | Frontier counts | Accepted states | Block calls |
|---|---|---|---:|---|---:|---:|
| DES | NUL | forward | 1 | 0 | 0 | 1 |
| DES | NUL | full hex reverse | 4 | 1,6,2,0 | 9 | 10 |
| DES | NUL | byte reverse | 1 | 0 | 0 | 1 |
| DES | NUL | nibble swap | 4 | 1,5,1,0 | 7 | 8 |
| DES | ASCII-0 | forward | 1 | 0 | 0 | 1 |
| DES | ASCII-0 | full hex reverse | 1 | 0 | 0 | 1 |
| DES | ASCII-0 | byte reverse | 4 | 1,6,1,0 | 8 | 9 |
| DES | ASCII-0 | nibble swap | 4 | 1,6,2,0 | 9 | 10 |
| AES-128 | NUL | forward | 1 | 0 | 0 | 1 |
| AES-128 | NUL | full hex reverse | 10 | 1,5,4,1,6,2,2,12,3,0 | 36 | 37 |
| AES-128 | NUL | byte reverse | 7 | 1,6,1,1,6,3,0 | 18 | 19 |
| AES-128 | NUL | nibble swap | 4 | 1,6,1,0 | 8 | 9 |
| AES-128 | ASCII-0 | forward | 1 | 0 | 0 | 1 |
| AES-128 | ASCII-0 | full hex reverse | 1 | 0 | 0 | 1 |
| AES-128 | ASCII-0 | byte reverse | 1 | 0 | 0 | 1 |
| AES-128 | ASCII-0 | nibble swap | 1 | 0 | 0 | 1 |

Across the 16 separately scoped contexts, the saved accounting contains 95 accepted intermediate states and 111 block calls. These totals describe the certificate workload; they are not additional hypotheses.

This is a finite exclusion only for the exact fixed-key, fixed-IV, printable-ASCII model above. It does not cover other malformed keys, arbitrary IVs, other cipher conventions, larger plaintext alphabets, insertion/deletion repairs, or unrelated families.

## Integrity and reproduction

- `target_results.json`: 13,707 bytes; SHA-256 `95e2fd9023cf6a7ceb4f570d7cec4a4e0191b2aebde002b54e564b15c649a69d`
- `target_gate.json`: SHA-256 `516804c6eb3c99755fee1fd0fe9474824c6a47bbf772c6d9886deb03e6e441b8`
- `run_target.py`: SHA-256 `dfd41b1dfcd5c1f3b62465478fb4ecfda20973a5a29a1c480f9bb4ed277456e9`
- parent `core.py`: SHA-256 `abadb49e68477b2875cffb712889798c8206ad3dde2357d7d71a5f5a09d1752e`
- parent `controls.py`: SHA-256 `86bbd8c080fb9de8c3404de9f09fad16e97e471f1a4641c84f7b65732445d565`
- parent `controls.json`: SHA-256 `ccf85c2f000b3269de87de7b3d636b30577dc964dbe24bc23b667af70e5ea837`

Registered one-time command:

```sh
python3 -B research/char_amsco/astra/lossy2013/target/run_target.py --run-target
```

Read-only certificate verification:

```sh
python3 -B research/char_amsco/astra/lossy2013/target/verify_results.py
```

The verifier is independent of the search geometry implementation for source-index and mask reconstruction. It replays only the short first-empty-prefix certificates, not a second 16-context full search. If the ledger contained survivors, it would verify every retained pair through library CFB8 decrypt/encrypt and the reconstructed source mask positions.

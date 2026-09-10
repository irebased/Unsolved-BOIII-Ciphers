# ASTRA synthetic case-preserving masked-CFB8 controls

This package extends the frozen lossy-AMSCO `2016` emission and cipher primitives with a complete, unscored frontier carrying CFB8 register, plaintext/ciphertext prefixes, and DFA state. The grammar permits repeated/leading/trailing spaces and lowercase, Titlecase, or ALLCAPS words. It contains no punctuation or Unicode and reads no Rev7 data.

Four controls are complete: 99-byte and 819-byte synthetic passages under DES/NUL and AES-128/ASCII-zero. PyCryptodome CFB8 agrees with the reused manual recurrence; every planted path is retained and every saved solution is re-encryption checked. Maximum frontier sizes are 56, 58, 100, and 62; block calls are 971, 1,036, 8,748, and 8,133 respectively. The 100,000 frontier and 5,000,000 accepted-state caps are explicit incomplete limits, though none was reached here.

An independently expressed regex is compared exhaustively on all 19,531 strings over reduced alphabet `aAbB ` for lengths 0..6, plus rejected `aA`, `ABc`, and `aBc`. Reproduce with:

```sh
python3 -B research/rev7-20260909-codex/homophonic/lossy2016_case_controls/case_frontier.py --regenerate /tmp/case-controls.json
```

Identity: ASTRA.

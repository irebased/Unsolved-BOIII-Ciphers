# Seeded full-length positive supplement

Identity: **ASTRA**

The all-IV full655 dropped-column-1 plant is correctly reported INCOMPLETE at five million accepted states, before its truth root. This separate synthetic supplement tests the same full-length masked suffix search without changing that result or its cap.

The original source map omits natural hexadecimal indices 2, 8, and 14 from the first 16 characters. `seeded_control.py` appends only those three indices and their planted truth values (`6A2`) to the explicit reconstruction map and observation. This makes all eight initial ciphertext bytes known and reduces the compatible-register set from 4,096 to one. Every later lossy source constraint remains unchanged.

The one-root search completes with 182 terminal candidates, 123,589 accepted states, 123,394 DES block calls, and maximum frontier 2,149. The exact planted full ciphertext and suffix occur once. Every terminal candidate is independently checked against the **original unaugmented** 1,092-character legacy emission, PyCryptodome suffix CFB8, the separate manual recurrence, the independent Unicode prefix oracle, the three appended planted nibbles, and exact hashes and lengths.

This is a seeded initial-register positive control. It does not complete the original 4,096-root search, add target coverage, or make the planted nibbles known for Rev7.

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/seeded_control.py
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/seeded_control.py --regenerate /tmp/seeded.json
```

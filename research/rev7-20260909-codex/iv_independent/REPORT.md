# IV-independent window geometry

<!-- identity: ASTRA -->

Structural measurement of the pinned 1092-hex-symbol Rev7 ciphertext. No crypto, key, IV, or plaintext evaluation was performed. `target_evaluated: true` means only that target text geometry was measured; `crypto_evaluated: false`.

| Orientation | BS | windows | min k | P(16,k) | minimizers | anchor contained |
|---|---:|---:|---:|---:|---:|
| byte_reverse | 16 | 530 | 12 | 871782912000 | 28 | 8 |
| byte_reverse | 8 | 538 | 7 | 57657600 | 4 | 2 |
| forward | 16 | 530 | 12 | 871782912000 | 28 | 8 |
| forward | 8 | 538 | 7 | 57657600 | 4 | 2 |
| nibble_swap | 16 | 530 | 12 | 871782912000 | 28 | 8 |
| nibble_swap | 8 | 538 | 7 | 57657600 | 4 | 2 |
| reverse | 16 | 530 | 12 | 871782912000 | 28 | 8 |
| reverse | 8 | 538 | 7 | 57657600 | 4 | 2 |

All orientations have identical histograms: BS8 `{'10': 110, '11': 164, '12': 120, '13': 62, '14': 10, '15': 3, '7': 4, '8': 18, '9': 47}` and BS16 `{'12': 28, '13': 92, '14': 184, '15': 150, '16': 76}`. The full endpoint/window records, all minimizer windows, anchor containment lists, and greedy symbol-addition estimates are in `geometry.json`.

The minimum-set anchor is selected among minimizers by maximum contained-window count (then lowest endpoint). Greedy additions select the symbol maximizing newly fully bound windows; this is descriptive geometry only and does not establish feasibility or recover plaintext.

Run: `python3 research/rev7-20260909-codex/iv_independent/geometry.py`

Source hashes and canonical hex hash are embedded in `geometry.json`.

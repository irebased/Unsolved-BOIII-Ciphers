# DE6 historical homophonic board reference (ASTRA)

I inspected the original-resolution image `lavender/src/assets/bo3/de/de_6_ref.webp` directly and manually transcribed every printed two-digit code from rows A through Z. The image SHA-256 is `93fc3bc1107cdae631993476f014ea0369610e95ff091837b3221ab451a613bd`.

The transcription is:

- A: 56 35 14 93 72 51
- B: 30 09
- C: 88 67 46
- D: 25 04 83 62 41
- E: 20 99 78 57 36 15 94 73 52 31 10 89 68 47 26 05
- F: 84 63
- G: 42 21 00
- H: 79 58 37 16
- I: 95 74 53 32 11 90 69
- J: 48
- K: 27
- L: 06 85 64
- M: 43 22 01 80
- N: 59 38 17 96 75 54 33 12 91
- O: 70 49 28
- P: 07
- Q: 86
- R: 65 44 23 02 81 60 39
- S: 18 97 76 55 34 13 92
- T: 71 50 29 08 87 66
- U: 45 24 03 82
- V: 61
- W: 40
- X: 19
- Y: 98
- Z: 77

The 100 natural-slot codes cover 00 through 99 exactly once. They begin 56, 35, 14, 93, 72, 51 and advance by 79 modulo 100. Since `79 * 64 mod 100 = 56`, this identifies parameters `a=79, b=64`. The independent literal transcription matches `cryptool100.controls.board(79,64)` in all 100 positions and all 26 letter allocations. There are no mismatches.

## Existing target rows

No target search was rerun. The script read the frozen 64,000-row NDJSON ledger, selected the single `a=79,b=64` row in each of its 16 hex/decimal-orientation paths, and ranked each within its saved 4,000-row path using the frozen rule `(-score_per_tetragram, a, b)`.

| Path | Rank / 4000 | Score |
|---|---:|---:|
| byte_reverse / digit_reverse | 841 | -13.008661464384543 |
| byte_reverse / identity | 2853 | -13.017926236274995 |
| byte_reverse / pair_reverse | 937 | -13.009119639334852 |
| byte_reverse / swap_within_pair | 3252 | -13.020042716215634 |
| forward / digit_reverse | 1705 | -13.013207087491240 |
| forward / identity | 2670 | -13.016867996304672 |
| forward / pair_reverse | 2458 | -13.016248965605270 |
| forward / swap_within_pair | 3851 | -13.024894706796317 |
| full_hex_reverse / digit_reverse | 2150 | -13.014571694935551 |
| full_hex_reverse / identity | 833 | -13.008841285813030 |
| full_hex_reverse / pair_reverse | 685 | -13.007962867271190 |
| full_hex_reverse / swap_within_pair | 3419 | -13.020921134757472 |
| nibble_swap / digit_reverse | 2343 | -13.015809756334350 |
| nibble_swap / identity | 3014 | -13.018804654816835 |
| nibble_swap / pair_reverse | 1068 | -13.009899525783345 |
| nibble_swap / swap_within_pair | 522 | -13.006105775172987 |

`target_rows_a79_b64.json` retains all 16 complete original candidate rows, each full plaintext, a 120-character plaintext prefix, exact score, hash, flags, and within-path rank. None of the prefixes is coherent plaintext. That is a visual observation; the sibling-trained score is a ranking heuristic and does not exclude a candidate.

## Files and verification

- `board.json`: manual transcription and exact generator comparison; SHA-256 `1dcf3db0ff3bf3f4d0d8b0b4906e3e59530566bcce13ec87e94463ac0ae13441`
- `target_rows_a79_b64.json`: all 16 saved rows and ranks; SHA-256 `3206dd5d080f06d07acaac94f7bc1069a29bb075743627827b5c5a4ae7f7146b`
- `verify_reference.py`: SHA-256 `9bdd3f1a60d6bb7a9cc36e2a9cde4dbe95201ed36bb1e6907a2f1b3a2802292d`
- Frozen generator source: `1d4bfae906bc01815866298aa9740ab283393dffa5275aed0b3dd2ba1648b567`
- Frozen target NDJSON: `426a5be079cf553ba657e3bb3f9d4e8153ee15422efc0e8793e1840249dcac39`

Fresh-checkout portability is verified through the published compressed ledger. When the raw NDJSON is absent, the verifier validates `results.pack.json` SHA-256 `625517b3832a7a14c42d90ff9cb1c7fca42d7abe571561727ab5c017bb89f3d8` and `pack_results.py` SHA-256 `8ae2d148942e75d45c15c75109ce95a47c712d067bd79592ba5ac0de7cd4bbd5`, performs bounded Base85/zlib decoding in memory, and requires the exact 67,783,676-byte raw SHA-256. The default verification exercised both the local raw route and forced packed-memory route without moving or deleting shared files; both reproduced the unchanged 16-row artifact.

Read-only verification:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/de6_reference/verify_reference.py
```

The verifier repeats the exact board comparison and re-derives all 16 selections and ranks from the saved ledger. It performs no target cryptographic or enumeration rerun.

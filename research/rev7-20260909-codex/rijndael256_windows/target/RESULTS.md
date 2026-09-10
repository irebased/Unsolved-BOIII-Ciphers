# Rijndael-256 ECB/CBC known-window results (ASTRA)

The preregistered run completed all 24 cells and all 11,208 context rows without a cap or resume. It retained no candidate windows. Of the complete rows, 11,006 were rejected when a byte fell outside A105 and 202 were rejected at a strict five-sequence FSA transition after the current byte passed A105.

Each row preserves its 64 returned plaintext bytes, two returned 32-byte blocks, input-window SHA-256, classification, and exact first rejection witness. ECB tests two complete consecutive block hypotheses. CBC tests the IV-independent `D(C1) xor C0 || D(C2) xor C1`. No trimming, unpadding, byte insertion, or framing fit was applied.

| Cell | Rows | A105 rejects | FSA rejects | Retained |
|---|---:|---:|---:|---:|
| `k128|forward|ecb` | 483 | 472 | 11 | 0 |
| `k128|forward|cbc` | 451 | 444 | 7 | 0 |
| `k128|full_hex_reverse|ecb` | 483 | 471 | 12 | 0 |
| `k128|full_hex_reverse|cbc` | 451 | 445 | 6 | 0 |
| `k128|byte_reverse|ecb` | 483 | 477 | 6 | 0 |
| `k128|byte_reverse|cbc` | 451 | 446 | 5 | 0 |
| `k128|nibble_swap|ecb` | 483 | 477 | 6 | 0 |
| `k128|nibble_swap|cbc` | 451 | 443 | 8 | 0 |
| `k192|forward|ecb` | 483 | 471 | 12 | 0 |
| `k192|forward|cbc` | 451 | 446 | 5 | 0 |
| `k192|full_hex_reverse|ecb` | 483 | 478 | 5 | 0 |
| `k192|full_hex_reverse|cbc` | 451 | 442 | 9 | 0 |
| `k192|byte_reverse|ecb` | 483 | 474 | 9 | 0 |
| `k192|byte_reverse|cbc` | 451 | 445 | 6 | 0 |
| `k192|nibble_swap|ecb` | 483 | 473 | 10 | 0 |
| `k192|nibble_swap|cbc` | 451 | 440 | 11 | 0 |
| `k256|forward|ecb` | 483 | 470 | 13 | 0 |
| `k256|forward|cbc` | 451 | 443 | 8 | 0 |
| `k256|full_hex_reverse|ecb` | 483 | 473 | 10 | 0 |
| `k256|full_hex_reverse|cbc` | 451 | 441 | 10 | 0 |
| `k256|byte_reverse|ecb` | 483 | 475 | 8 | 0 |
| `k256|byte_reverse|cbc` | 451 | 444 | 7 | 0 |
| `k256|nibble_swap|ecb` | 483 | 473 | 10 | 0 |
| `k256|nibble_swap|cbc` | 451 | 443 | 8 | 0 |

The original result is 8,339,129 bytes with SHA-256 `c50a7103736310aa6aba1c58834d62554d11aaec22bbf1430e35d56efbb4890d`. The lossless pack reconstructs those exact bytes; its SHA-256 is `7cc9927dbd1a53ff87ded3c80980518faaf2b2d44cc05ccd5deaf3c019acd5b7`, and its compressed zlib payload is 1,188,984 bytes. The gate SHA-256 is `a9611eb904ae8575f6b85368f339be69500bae45bd15710abe77d77ee580464d`; the frozen driver SHA-256 is `e9796cad76be085775e6c0532faf11f1390b0792863d391be2381c965554f416`.

Read-only portable verification:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_windows/target/pack_results.py
python3 -S -B research/rev7-20260909-codex/rijndael256_windows/target/verify_results.py
```

The verifier reconstructs the original bytes, checks every gate and artifact pin, reconstructs all four canonical orientations, verifies all cell IDs and offsets, recomputes every input-window hash, checks the two-block/full-plaintext relationship, and replays every stored A105/FSA witness plus an independent regex endpoint oracle. This is a structural and endpoint replay of the stored result, not a second cryptographic target enumeration.

Finite limits: the result covers only the registered 256-bit-block Rijndael primitive, three explicit NUL-padded `Zombies` keys, ECB/CBC window equations, four orientations, the exact 546-byte source, and the A105/five-sequence cut endpoint. A rejected window rules out that exact aligned window hypothesis under those parameters. It does not cover other keys, modes, padding/framing rules, encodings, or plaintext alphabets.

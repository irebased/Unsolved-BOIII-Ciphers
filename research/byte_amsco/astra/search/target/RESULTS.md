# Byte-AMSCO all-IV target results (ASTRA)

The single preregistered run completed successfully in execution session `94732` using immutable commit `9afccd6b66dc56684c88c774dd7eccfa73b2d898`, gate SHA-256 `61793d92916e57959f2cca9f5df32df8cc1cdcf4e06781eaa3f19193e33a49c2`, and driver SHA-256 `a3b865878f889799fbbebb7d8de3956677fdad0696ee96434f7e30982cde3ec3`. The process exited zero and was not restarted.

## Result

All 64 geometries completed without a cap:

- 3,272,896 AMSCO orders examined;
- 22,910,272 seven-backend contexts examined;
- 22,463,286 rejected by the A105 necessary byte predicate;
- 446,986 were rejected at a strict FSA transition after the current byte passed A105;
- zero terminal-only rejections;
- zero retained candidates; and
- zero unexamined orders or backend contexts.

Every width/start/orientation cell reports exactly `width!` orders and `width! × 7` backend contexts. Because no suffix survived, no candidate plaintext or two-IV survivor replay was required. Rejection digests record the production callback output for every negative context; they are reproducibility coordinates rather than an independent second enumeration.

The complete compact JSON result is 230,874 bytes with SHA-256 `baf3fc16f2eb84008b75fc80521502134945fdeece075183fa61050c19779cdd`. The driver did not persist elapsed timing, so this report does not infer it from polling or file timestamps.

## Finite scope

The run covers the byte-unit AMSCO analogue at widths 2–9, both continuous 1/2 starts, every column permutation, four canonical byte orientations, and seven fixed-`Zombies` CFB8 backends. For each backend, the tested suffix starts after its 8- or 16-byte block size and is independent of every external IV. The endpoint permits TAB/LF/CR, ASCII 32–126, and UTF-8 `E2 80 93/94/98/99/A6`, starting from states `{0,1,2}` and ending in state 0.

This result does not cover character-unit AMSCO semantics, widths outside 2–9, other keys or modes, the IV-dependent prefix, encodings, framing, padding changes, or other endpoint alphabets. It is a finite negative result for the registered model, not attribution of an intended construction.

## Verification

Portable verification uses only the Python standard library:

```sh
python3 -S -B research/byte_amsco/astra/search/target/verify_results.py
```

The verifier checks the immutable result, gate, driver, MDX, and every gate-pinned artifact; independently reconstructs all four canonical orientations; verifies all 64 cell IDs; checks every factorial, backend, class, and zero-unexamined total; validates negative digest and witness-example formats; and checks every retained suffix/replay field if present. It does not repeat the 22.9-million-context cryptographic enumeration.

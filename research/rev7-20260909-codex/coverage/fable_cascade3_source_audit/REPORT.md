# FABLE cascade3 source and result audit

Identity: **ASTRA**. Seven currently readable FABLE artifacts were copied byte-for-byte under `upstream/`, preserving their relative paths. Their SHA-256 values and sizes are recorded in `audit.json`.

The captured source declares 46 layer choices at each of three decrypt layers, four optional reverse boundaries, and four input orientations. Its arithmetic is `4 × 46³ × 16 = 6,229,504` target chains, or 1,557,376 per orientation. The saved result is internally consistent with that arithmetic: both target and negative histograms contain 6,229,504 observations; each of their four orientation counts is 1,557,376; both longest-run and valid-count histograms sum exactly. The saved target maximum is 21 and the saved negative maximum is 23. The saved positive control reports rank 1, longest run 316, and two tied paths over one orientation's 1,557,376 chains.

These are source/result consistency findings. They are not an independent cipher replay. `scan3.js` imports missing `cascade/scan.js` for the actual 46-entry `LAYER_OPTS` and `blockSizeFor`; the planted ciphertext/plaintext, negative seed, and pinned mcrypt JS/WASM runtime/build evidence are also absent. Consequently this package does not independently establish the option union, successful output lengths/alignment, cipher bytes, planted rank, target maximum, or the saved null comparison.

The readable library reports CFB8 mode integer 0, an ASCII-`0` IV repeated to each block size, literal keys `Zombies` and `ZOMBIES`, and a Loki97 fix that supplies a full 32-byte zero-backed key buffer. It catches failed decrypt calls before counting leaves; the exact saved counts are consistent with no skipped combination, conditional on the missing 46-option table and runtime.

`controls.js` safely imports only the helper definitions and never calls `loadMcrypt`. On Node v26.4.0, `scoreTail(buf,0)` gives `longestRun=validCount=tailLen=546` for synthetic binary, octal, decimal, uppercase/lowercase hex, Base32, Base64, and common allowed German UTF-8 text. This verifies those complete tails pass the captured score function; it provides no English ranking or target conclusion.

Reproduce the target-free audit from the isolated repository root:

```sh
node research/rev7-20260909-codex/coverage/fable_cascade3_source_audit/controls.js
python3 -B research/rev7-20260909-codex/coverage/fable_cascade3_source_audit/audit.py
```

Generation is separate and refuses existing output. No new target decrypt or full cascade sweep was run.

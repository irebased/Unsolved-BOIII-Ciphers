# Rev7 image transcription reconciliation

Identity: ASTRA. Target evaluated: false.

A blind manual transcription was frozen before any repository text comparison. It contained 1,092 hexadecimal glyphs and had joined SHA-256 475adfad88ba31e26e24889e8f0935acc2ce4583177c432b5bc3ae70f2385c79.

Root requested visual re-examination of exactly two coordinates without revealing canonical values. The independent crop adjudication changed:

- line 6, group 7, character 4: 4 to A, giving FABA7;
- line 14, group 7, character 3: E to F, giving 36F4F.

Both decisions had high visual confidence. In row 6, the first glyph matches the pointed and crossbarred A forms in the same row and lacks the construction of 4. In row 14, the second glyph lacks the bottom stroke present on same-row E forms and matches same-row F forms. Exact row-crop hashes and fuller exemplar notes are preserved in adjudication.json.

Only after adjudication was frozen was the corrected derivative compared mechanically with the repository MDX and dataset. All 1,092 glyphs match both records exactly. The joined corrected SHA-256 is 5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c.

The original transcription and adjudication ledger remain unchanged. The MDX and dataset were read only and were not edited. No cipher search or target experiment was run.

Verification command:

    python3 -B research/rev7-20260909-codex/coverage/rev7_image_transcription/verify_reconciliation.py

The verifier reapplies exactly the two adjudicated edits, checks their joined positions 381 and 935, verifies all frozen hashes, independently extracts the MDX and dataset ciphertexts, and requires exact equality.

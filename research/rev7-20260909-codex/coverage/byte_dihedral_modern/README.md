# Byte-dihedral preprocessing before a modern layer

Identity: **ASTRA**. This target-inert package tests the 16 byte permutations `ROL8(x,k)` and `ROL8(bit_reverse8(x),k)` before the accepted 312-context first-layer runtime, across the five frozen ciphertext orientations. Exact transformed-input hashes are deduplicated before crypto.

The endpoint records the accepted occupancy screen on the full output and one-block-skipped block-cipher tail, plus the fraction of bytes in TAB/LF/CR or ASCII 32..126 on those windows; ratio at least 0.75 is retained. These are inspection screens, not language proofs.

Synthetic controls prove all 16 maps and inverses on all 256 bytes and run a complete planted Twofish/CFB8 pipeline through each orientation. `rotate:0` repeats the five old direct first-layer inputs (1,560 unique input/context evaluations). `rotate:4` is byte nibble swap; across the four canonical non-G orientations it adds four more logical aliases of those prior inputs, so 2,808 logical labels point at the five already evaluated input/context results. Exact dedup catches these aliases. Inbox evidence records direct bit-transform sweeps, but no composition of the byte-dihedral family with these modern contexts.

Run `node controls.js` for read-only verification. Generate only to a new path with `node controls.js --generate NEW_PATH`. `node run_target.js` performs source-only preflight. A target run requires a separately authorized, frozen `target_gate.json`; this package does not create or execute it during preparation.

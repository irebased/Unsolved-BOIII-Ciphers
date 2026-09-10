# ASTRA replay of FABLE byte-set results

Identity: ASTRA. This package verifies FABLE's existing 184 direct-decryption outputs; it adds no target contexts. All 184 saved ciphertext-input hashes, decrypted-output hashes and outside-byte counts match a replay through the supplied WASM. The byte-set construction and count are independently implemented. This is not an independent block-cipher implementation.

The original ledger wrongly labels 32 stream-cipher rows as CFB8. The frozen original is retained as evidence; `verified_outputs.json` records the actual invocation mode and all complete output bytes. There are 152 CFB8 rows and 32 stream rows. The minimum outside-byte count is 153. Every CFB8 row exceeds its single-edit allowance `blockSize + 1`; the smallest margin is 136. Stream rows reject only the undamaged endpoint under their fixed invocations.

The endpoint byte union consists of the 165 bytes derived in the neighboring `transposition_byte_bag` proof package. These statements concern the declared finite endpoint and supplied keys/runtime only; no plaintext was recovered.

## Reproduction

Read-only verification of every saved output byte and count:

```sh
python3 -B research/rev7-20260909-codex/coverage/fable_bytebag_replay/verify_outputs.py
```

`replay.js` is the unchanged one-shot script used for the original root replay. To rerun the supplied WASM, copy `replay.js`, `manifest.json` and `source/` into a fresh directory, decode `source/old-ciphers/js/mcrypt.wasm.base64` to the adjacent `mcrypt.wasm`, then run `node replay.js` there. It refuses an existing `verified_outputs.json`. The source bytes are unchanged; the sibling directory layout restores the literal `../../old-ciphers` import that was broken in FABLE's flattened mirror. The original input/ledger are preserved under `source/record/`.

The manifest records the exact original absolute mirror paths, byte counts and SHA-256 hashes. The decoded WASM SHA-256 is `60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7`; transport is base64 to preserve binary bytes. All source/runtime files were supplied by FABLE through the shared public-cipher research mirror. FABLE subsequently corrected its own metadata; this replay retains the original evidence and annotates the correction explicitly.

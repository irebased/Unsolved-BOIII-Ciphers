# Native Blowfish-compat CFB8 controls

Identity: ASTRA. Target evaluated: false.

This separate engine uses the exact block adapter `word_reverse(BF(key, word_reverse(block)))`, where `word_reverse` reverses bytes within each 32-bit half while preserving half order. The synced WASM vector subset gates every later control: all 200 BF-compat block vectors must match both the independent Python adapter and the native OpenSSL adapter. Four alternative transforms are counted and must match zero vectors.

The supplied WASM block vectors all use 16-byte keys. They establish the word-reversal transform for those vectors. They do not directly establish a seven-byte `Zombies` WASM result or a historical frontend key convention. The fixed native lane passes raw seven-byte `Zombies` directly to OpenSSL `BF_set_key`; its CFB8 comparison against a separate Python implementation is an internal implementation control, explicitly not a direct WASM fixed-key comparison.

Build and run:

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/hex_cfb/native_compat
clang++ -std=c++17 -O3 -Wno-deprecated-declarations native_compat.cpp -o native_compat \
  -I/opt/homebrew/Cellar/openssl@3/3.6.3/include \
  -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto \
  -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib
python3 -B controls.py
```

Controls cover all byte values in fixed-key CFB8 encryption/decryption, a complete four-unknown mixed-punctuation plant checked against all 24 naive permutations and the Python DFS, and deterministic 250,000/1,000,000-node full-map capped prefixes compared exactly with Python. Capped controls prove implementation parity only and make no plant-recovery or completeness claim.

`wasm_bfcompat_vectors.json` retains only the required BF-compat vectors plus the SHA-256 and path provenance of the synced full vector file. No FABLE artifact is modified. No Rev7 ciphertext is read or evaluated.
## Pinned-source raw-key check

The complete reproducible harness is `source_check.py`. Its default output is the frozen `source_check.json`, so a default run refuses to overwrite it. Use `--verify-existing` for a non-mutating ledger check, or pass a new `--output` path for an intentional full rebuild and reproduction. A fresh result records compiler commands/version, source and helper hashes, binary hashes, platform byte order, pointer width, and both libmcrypt context sizes.

The preserved upstream files and `source/COPYING.LIB` provide the exact source and license text. One of the three ECB blocks, `83b57b2c3434697f`, is the known first eight Rev7 bytes supplied in the task context. The check did not read the Rev7 file and performed no Rev7 decryption or search.

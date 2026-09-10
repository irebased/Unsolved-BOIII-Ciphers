# Rijndael-256 CFB8 interval adapter control plan

Identity: ASTRA. Synthetic controls only. Target evaluated: false.

This package will add three source-controlled 32-byte-block CFB8 backends to the accepted seven-backend interval runtime:

- `rijndael256_key16`: ASCII `Zombies` followed by nine NUL bytes;
- `rijndael256_key24`: ASCII `Zombies` followed by seventeen NUL bytes;
- `rijndael256_key32`: ASCII `Zombies` followed by twenty-five NUL bytes.

The primitive package is read-only and pinned:

- `rijndael256_controls/controls.json`: `2e164a7b6091f5a1c76a1863cd45ddb2c919597350ff20e3ce52c131ed9c804c`;
- `controls.py`: `c35dde4e66b4a5633c0b0d14086bb1011ae313448d4e460ef405dd53d29f6cb2`;
- `build_source.py`: `d32cac36412340865b2fd28d8b6437f9c2f508cd229c58881c3285d3e3039961`;
- untouched JavaScript harness `js_blocks.js`: `ceefc2c2c15b7cb60b07ba14539c1ec99bda682409a728bc2fa04ee4df292f52`;
- untouched JavaScrypt source `source/aes.js`: `c8d6903ff7d6b090b2050f1c59dcf63ee08ac0c084caa11f9912bf5b20f90a8a`;
- historical C source `source/rijndael-256.c`: `fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821`;
- Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`.

The accepted seven-backend runtime is pinned by `runtime.py` SHA-256 `8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4` and ledger SHA-256 `483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5`. The accepted interval-transform proof is pinned by `interval_extension.py` SHA-256 `b704413c6fddd24128fe1d2185de2aff780a6d8b7c5924f9dfebb35fcf561dae` and ledger `43b7f352f14cc87b1c0452338334f9dbde3db74abdfd16dab2ff726adb269037`.

## Adapter theorem

For any known ciphertext interval `[L,R)`, a 32-byte CFB8 layer exposes exactly plaintext interval `[min(L+32,R),R)`. For every retained byte, its 32-byte feedback register and current ciphertext byte lie wholly inside the known input interval. Empty output is inconclusive.

The adapter will schedule its key once and expose `encrypt_block`, CFB8 encrypt/decrypt, and `interval_decrypt` with the same interface as the accepted runtime. It will neither frame, pad, nor unpad.

## Primitive controls

The fixed control payload is bytes 0 through 255. For each of the three keys and two unrelated 32-byte IVs:

1. historical C CFB8 encrypts and decrypts the complete 256-byte stream;
2. an independent Node VM harness loads the untouched `aes.js`, expands the key once, and performs the full CFB8 loop inside JavaScript;
3. C and JavaScript ciphertexts match byte-for-byte;
4. both round trips are exact.

The Node process receives all six jobs in one JSON batch. It is not launched once per byte.

For each key, seven known intervals over a controlled full ciphertext test empty, exact-boundary, internal, and nonzero outputs. Adapter bytes and offsets must equal slices from full reference decryption under both IVs.

## Mixed cascade controls

The existing seven backends are AES-128, DES, Blowfish, Blowfish compatibility, RC2, Twofish, and Loki97. Interlayer involutions are identity, byte reversal, nibble swap, and full hexadecimal-symbol reversal.

Depth two enumerates:

- each existing backend;
- each of the three Rijndael-256 keys;
- Rijndael in either layer position;
- all four interlayer transforms.

This is 168 recipes and 336 executions under two IV suites.

Depth three uses seven ordered cyclic existing-backend neighbor pairs. For each pair it enumerates:

- each Rijndael key;
- Rijndael in each of three layer positions;
- all 16 ordered transform pairs.

This is 1,008 recipes and 2,016 executions under two IV suites.

Total: 1,176 recipes and 2,352 complete cascade executions. Every recipe uses a fully valid synthetic plaintext containing all five registered UTF-8 punctuation sequences. Full mode encryption/decryption must round-trip. The interval recurrence and transform geometry must recover exactly the corresponding plaintext interval under both IV suites.

A separately implemented boundary-aware endpoint oracle checks the final known interval. Internal intermediate intervals are recorded but never filtered: controls must include cases where an intermediate interval fails the text oracle and the final interval succeeds, proving that intermediate rejection would be unsound.

## Limits

These controls cover direct same-length binary CFB8 layers and only the four registered involutions. They do not cover encoding, transposition, framing, padding changes, truncation, other key lengths, other modes, or arbitrary interlayer relocation. They do not read Rev7, create a target driver or gate, or authorize a cascade target search.

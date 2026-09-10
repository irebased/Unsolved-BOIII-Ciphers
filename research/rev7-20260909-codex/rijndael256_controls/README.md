# Rijndael-256 block controls (ASTRA)

This synthetic-only package checks the historical libmcrypt Rijndael-256 primitive against an untouched JavaScrypt reference. It never reads or evaluates the Rev7 ciphertext.

The block size is 256 bits (32 bytes). The three registered keys are the ASCII bytes `Zombies` followed by NUL bytes to exactly 16, 24, or 32 bytes. This padding is explicit input construction, not behavior inferred from the C primitive.

`controls.py` verifies the embedded C known-answer encryption test, the C block/key-size API, C/JavaScript block encryption and decryption at all three supported key sizes, manual ECB, and manual CBC for one, two, and three blocks under three 32-byte IVs. Framing rows distinguish an external `IV || ciphertext` frame, an explicitly stripped trailing frame, a plaintext header encrypted as data, and trailing NUL plaintext bytes that remain after decryption. Neither implementation implicitly frames, pads, nor unpads these control messages.

The historical C self-test's post-decryption `strcmp` is weak because the plaintext begins with NUL. The package therefore performs and asserts a separate full 32-byte KAT decryption comparison in both C and JavaScript.

The JavaScript harness loads the exact copied `aes.js` in a Node `vm`, sets `blockSizeInBits = 256` and `keySizeInBits` to 128, 192, or 256 immediately before each `keyExpansion`, and calls only the block `encrypt`/`decrypt` functions. The C and JavaScript block primitives are independent; shared, explicitly reviewed Python equations compose each primitive into ECB and CBC; JavaScript's randomized wrapper is not used.

The C source and LGPL file are pinned to Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`. The untouched JavaScript source retains its full license notice. No compiled binary is part of the package.

Default verification is read-only and checks hashes plus all stored structural/equality assertions:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_controls/controls.py
```

To cryptographically regenerate into a new path (Node, clang, and a temporary shared library are used):

```sh
python3 -B research/rev7-20260909-codex/rijndael256_controls/controls.py --regenerate /tmp/rijndael256-controls.json
```

Regeneration refuses an existing output. The ledger records runtime versions and the temporary build command, but does not record or require the machine-specific binary hash.

Limits: these controls establish agreement for the recorded synthetic vectors and exact parameter conventions. They do not evaluate Rev7, prove security, cover nonstandard key lengths, define implicit padding, or establish a target-search result.

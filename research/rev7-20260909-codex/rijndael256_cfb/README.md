# Rijndael-256 CFB8 interval controls (ASTRA)

Identity: ASTRA. This is a synthetic-only control package. It did not read or evaluate Rev7 and contains no target driver or gate.

The package adds three 32-byte-block Rijndael-256 backends to the accepted seven-backend CFB8 cascade runtime. Their keys are the raw bytes `Zombies` followed by NUL bytes to exactly 16, 24, or 32 bytes. The adapter schedules each key once, applies byte-segment CFB, and exposes the exact interval recurrence

`[L,R) -> [min(L+32,R),R)`.

Every retained plaintext byte has both its current ciphertext byte and its preceding 32-byte feedback register inside the known input interval. This is the only basis for IV independence.

## Evidence

The ledger contains six complete 256-byte primitive streams: three keys under two unrelated IVs. Historical C encrypt/decrypt agrees byte-for-byte with a Node VM harness that loads the untouched JavaScript `aes.js`, expands each key once, and runs the full CFB8 loop inside JavaScript. The exact plaintext, ciphertext, key, and IV bytes are retained.

A separate direct control decrypts the same fixed ciphertext under two different IVs for each key. The first 32 plaintext bytes differ and every byte from offset 32 onward is identical. This directly establishes the claimed CFB8 suffix property; comparisons between freshly encrypted ciphertexts are not used as that proof.

Twenty-one interval vectors cover seven boundaries for each key. The mixed grid contains 168 depth-two and 1,008 depth-three recipes. Depth three uses seven cyclic pairs of existing backends, with Rijndael placed in each layer position; it does not enumerate all 49 ordered existing-backend pairs. Each runs under two IV suites, for 1,176 recipes and 2,352 executions. It composes each Rijndael key with AES-128, DES, Blowfish, Blowfish compatibility, RC2 effective-1024, Twofish, and Loki97 through identity, byte reversal, nibble swap, or full hexadecimal-symbol reversal. Every exact interval matches the corresponding slice of full reference decryption.

The final interval is checked by a separately written endpoint oracle for TAB/LF/CR, ASCII 32 through 126, and UTF-8 `E2 80` followed by `93`, `94`, `98`, `99`, or `A6`. All 1,176 recipes contain intermediate binary intervals rejected by that oracle before the final interval succeeds. Those intermediate failures are recorded and never used to prune.

## Reproduction

The published ledger is a lossless `controls.pack.json` envelope. On a fresh checkout, first reconstruct the exact original bytes at the path expected by the existing verifier and downstream source gates:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_cfb/pack_controls.py --unpack research/rev7-20260909-codex/rijndael256_cfb/controls.json
```

Skip this step when that original file is already present; unpacking refuses an existing destination. Running `pack_controls.py` without arguments verifies the bounded lossless reconstruction in memory.

Default verification is read-only, uses the Python standard library, checks all pinned source/dependency hashes, and checks the retained ledger structure and byte hashes:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_cfb/controls.py
```

Cryptographic regeneration requires Python with PyCryptodome, Node, and clang. It builds unchanged historical sources only in a temporary directory and refuses an existing output:

```sh
python3 -B research/rev7-20260909-codex/rijndael256_cfb/controls.py --regenerate /tmp/rijndael256-cfb-controls.json
```

The generated ledger is compact JSON. Temporary build paths are normalized to `<temporary-build>`; machine binary hashes and tool versions remain evidence for the recorded run.

## Provenance and limits

The unchanged historical C source is [Distrotech/libmcrypt `rijndael-256.c` at commit `3bd338e`](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/rijndael-256.c), with its [LGPL license](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/COPYING.LIB). The independent JavaScript primitive is the unchanged JavaScrypt `aes.js` already pinned by the accepted primitive package and retains its license notice.

These controls establish only the stated raw-key, source-backed CFB8 interval model and registered same-length involutions. They do not emulate a full historical wrapper. They do not cover framing, implicit key handling, encoding, padding, transposition, insertion, deletion, truncation, other modes, or other keys. Intermediate binary endpoint failures cannot reject a cascade. Bytes outside the final interval remain unknown.

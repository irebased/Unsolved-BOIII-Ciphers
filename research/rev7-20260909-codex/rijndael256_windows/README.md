# Rijndael-256 known-window controls (ASTRA)

This package supplies synthetic controls for a prospective finite scan of 546-byte streams under Rijndael with 256-bit blocks. It imports the separately frozen C/JavaScript primitive package and contains no target extraction, target driver, gate, or target result.

For ECB, each 64-byte ciphertext window is interpreted as two consecutive aligned cipher blocks and returns both decrypted blocks. Offsets 0 through 482 give 483 windows. For CBC, each 96-byte window is interpreted as `C0 || C1 || C2`; it returns `D(C1) xor C0 || D(C2) xor C1`. Those 64 returned bytes are independent of every external IV. Offsets 0 through 450 give 451 windows. Bytes are retained exactly; the engine never trims or unpads. Its `collect_all` evidence path retains each window's two decrypted blocks, full 64 bytes, classification, and first rejection witness; a 483-row synthetic scan exercises this path.

The CBC equation follows NIST SP 800-38A section 6.2: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

The endpoint first applies A105 (`TAB`, `LF`, `CR`, printable ASCII, and the bytes of five registered UTF-8 punctuation sequences), then a strict FSA for `E2 80 {93,94,98,99,A6}`. Initial and terminal state sets are both `{0,1,2}` because both edges are cuts. A retained window means two complete consecutive aligned plaintext blocks under that window hypothesis. It does not establish that an arbitrary 64-byte substring is block-aligned or complete text.

Controls cover all 32 alignment residues for ECB and CBC, all three explicit `Zombies` plus NUL keys (16, 24, and 32 bytes), and all four canonical byte orientations, using 546-byte synthetic streams. Every retained synthetic window and representative A105/FSA-negative windows are replayed with the independent untouched JavaScript block primitive; negative plaintext is also checked by a separate regex oracle. CBC controls decrypt the same fixed ciphertext under two IVs and confirm only the first plaintext block changes. Separate regex-oracle fixtures cover left and right partial UTF-8 boundary states and an invalid sequence. Framing controls demonstrate the three explicit ways 544 aligned bytes plus two framing bytes total 546; no implicit framing is inferred.

Default verification is source/ledger structural and read-only:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_windows/controls.py
```

Cryptographic regeneration builds the pinned C primitive temporarily and writes only to a new caller-selected path:

```sh
python3 -B research/rev7-20260909-codex/rijndael256_windows/controls.py --regenerate /tmp/rijndael256-windows.json
```

This package does not evaluate Rev7. Its prospective arithmetic is `4 orientations × 3 keys × (483 ECB + 451 CBC) = 11,208` contexts. The controls do not cover other modes, block sizes, keys, padding rules, encodings, or added bytes.

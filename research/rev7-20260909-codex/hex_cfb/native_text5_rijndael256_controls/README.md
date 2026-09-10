# Rijndael-256 native text-five controls

Identity: **ASTRA**. This package is synthetic only. It does not read or evaluate Rev7 and contains no target driver or gate.

## Exact adapter

The engine preserves the frozen global 16-symbol hex-bijection DFS, search order, factorial accounting, node-cap semantics, and strict endpoint from `hex_cfb/native_text5`. Its only backend is the historical Rijndael-256 block primitive with a 32-byte block, the 16-byte key `Zombies` followed by nine NUL bytes, and an IV of 32 ASCII `0` bytes. The key schedule is created once per search. Every feedback register, ECB input/output buffer, and shift bound is 32 bytes.

`PARENT_DIFF.patch` is a review artifact against the frozen `native_text5/native_text5.cpp`. The new source removes unrelated cipher adapters and widens the feedback storage while leaving the DFS decisions and certificates unchanged. No compiled binary is retained.

The C primitive is the unchanged Distrotech/libmcrypt `rijndael-256.c` at commit `3bd338e2f808e985f5b229a7642d48c26615993f`, with its pinned headers and LGPL license. Primitive independence comes from the untouched JavaScrypt `aes.js` reference. The Python search reference uses the same pinned C primitive through the accepted `Rijndael256Backend`; its agreement with native code checks search and recurrence control flow, not an independent primitive implementation.

## Controls

- Four independent block vectors compare historical C with untouched JavaScript.
- A stream containing every byte value compares native CFB8, Python manual CFB8 over the same C primitive, and independent JavaScript CFB8, including encryption and decryption.
- A planted map with four unknown displayed symbols exhausts all 24 completions. Native DFS, Python DFS, and a separate direct 24-permutation oracle produce the same survivor set and recover the planted map/plaintext.
- Full 16-symbol fresh-root searches at 250,000 and then 1,000,000 nodes have exact native/Python prefix statistics and survivor sets. Both are capped and are not completeness claims; their weights are lower-bound certificates only and are not added together.

The endpoint accepts TAB/LF/CR, ASCII 32 through 126, and exactly UTF-8 `E2 80 93/94/98/99/A6`; terminal state must be zero.

Default verification is read-only and checks the frozen source closure and ledger structure:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/controls.py
```

Cryptographic regeneration builds only into a temporary directory and refuses an existing output:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/controls.py --regenerate /tmp/r256-native-controls.json
```

The finite controls cover only this one key, IV, endpoint, primitive, and global nibble-bijection model. They do not establish an exhaustive full-16 result or any Rev7 result.

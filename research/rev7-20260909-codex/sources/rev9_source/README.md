# Pinned-source Rev9 Twofish control

Identity: **ASTRA**. Target evaluated: **false**. No Rev7 file was read.

This control compiles the unchanged Twofish implementation and header from Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`:

- [twofish.c](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/twofish.c), SHA-256 `20e72e38b445868fe71a0274e0b9bd658c6f30cb1ad731eb3364d82e319af598`
- [twofish.h](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/twofish.h), SHA-256 `c233e43572b5837f9eddc3b6c3f495d91eaa858ade2f9eaf3bc2f959fe721a6b`
- [COPYING.LIB](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/COPYING.LIB), preserved SHA-256 `ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532`

The minimal build headers define only required fixed-width types, rotations, byte swapping, includes, and export macro. The algorithm source and header are unchanged.

The source self-test passes. An explicit repetition uses its exact 16-byte key `9f589f5cf6122c32b6bfec2f2ae8c35a`, plaintext `d491db16e7b1c39e86cb086b789f5419`, and expected ciphertext `019f9809de1711858faac3a3ba20fbc3`, including decrypt roundtrip. A separate 276-byte all-values CFB8 fixture roundtrips under the saved source primitive.

## Solved Rev9 replay

The complete repository ciphertext follows the documented chain:

1. Base64 decode to 809 bytes.
2. DES-CFB8 decrypt using `Zombies` plus one NUL byte and eight ASCII-zero IV bytes.
3. Decode 202 three-digit decimals to a Base64 byte string.
4. Reverse that byte string, strip outer whitespace, and Base64 decode to 149 bytes.
5. Twofish-CFB8 decrypt with `Zombies` selected to 16 key bytes and sixteen ASCII-zero IV bytes.

The output is 149 bytes and strict UTF-8. After stripping the final newline, it equals the complete recorded plaintext exactly. Both cipher layers re-encrypt to their exact inputs. `controls.json` preserves every full intermediate as hex plus SHA-256.

The decrypted bytes contain exactly one ellipsis encoded as `e280a6`, at byte offset 134 and character index 134. The editorial U+2026 glyph is therefore present in the original recovered bytes; it is not a later transcription replacement. This is useful endpoint evidence for this solved sibling only. It does not prove the language of Rev7 or evaluate any Rev7 hypothesis.

The seven-byte password follows libmcrypt fixed-key handling: Twofish selects declared length 16 and receives a zero-initialized maximum-size backing buffer. Twofish consumes the selected first 16 bytes. DES uses eight bytes, `5a6f6d6269657300`. See [the library key-memory audit](../../hex_cfb/native_siblings/LIBRARY_KEY_MEMORY.md) for the pinned allocation path.

## Reproduce

From this directory:

```sh
clang -shared -fPIC -O2 -Isource_build -Isource source/twofish.c -o source_build/libtwofish.so
python3 -B controls.py
```

The driver refuses to overwrite `controls.json`. Recorded tools are Python 3.9.6 and Apple clang 21.0.0 on little-endian macOS arm64.

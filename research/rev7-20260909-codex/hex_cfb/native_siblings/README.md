# Source-backed RC2 and Loki97 native controls

Identity: **ASTRA**. Target evaluated: **false**. No Rev7 file was read.

This directory adds RC2 and Loki97 to a copy of the accepted native ASCII-plus-four-UTF8 DFS engine. It links object files compiled from unchanged historical libmcrypt sources at Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`:

- [RC2 source](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/rc2.c)
- [RC2 header](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/rc2.h), which is genuinely empty
- [Loki97 source](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/loki97.c)
- [libmcrypt license](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/COPYING.LIB)

The minimal headers define only the fixed-width libmcrypt types, byte swaps, RC2 rotations, standard includes, and export macro needed to compile these modules. The historical algorithm files are unchanged. Key schedules are initialized once per cipher object and reused for block calls.

## Key conventions

RC2 reports no fixed supported-key-size list and a maximum of 128 bytes. Controls pass the raw seven bytes `5a6f6d62696573`. The actual C block result matches PyCryptodome ARC2 with `effective_keylen=1024` for keys of 5, 7, 16, and 128 bytes.

Loki97 reports supported sizes 16, 24, and 32 bytes. The seven-byte password selects metadata length 16. Its pinned key setup reads eight words and does not use the length argument, so the source-backed object retains a 32-byte zero-initialized key buffer containing `Zombies` followed by 25 NUL bytes while passing declared length 16. This records the tested fixed-key wrapper convention precisely.

## Controls

Both sources reproduce their embedded known-answer construction: maximum-size key byte `j` is `(j*2+10)%256`, and the plaintext is bytes `0..block_size-1`. RC2 returns `becbe4c8e6237a14`; Loki97 returns `8cb28c958024bae27a94c698f96f12a9`.

For each cipher, an all-256-byte CFB8 fixture plus an ASCII suffix matches the native engine byte-for-byte and decrypts exactly through a separate Python recurrence backed by the compiled source primitive. A mixed ASCII and UTF-8 punctuation plant leaves four unknown display-symbol mappings; the native and Python DFS statistics, mapping list, and full plaintexts match all 24 naive permutations, including exact plant recovery. Full-sixteen-symbol 250,000- and 1,000,000-node capped traversals match every Python statistic and survivor. These capped controls prove implementation parity and cap accounting only.

The real solved Rev5 chain is also replayed completely:

1. Base64-decode the 1,656-byte outer ciphertext.
2. RC2-CFB8 decrypt with raw `Zombies` and eight ASCII-zero IV bytes.
3. Strip six trailing LF bytes, reverse all 1,650 hex characters, and decode 825 bytes.
4. Standard Blowfish-CFB8 decrypt with raw `Zombies` and eight ASCII-zero IV bytes.
5. Base64-decode 615 bytes.
6. Loki97-CFB8 decrypt with the fixed-key convention above and sixteen ASCII-zero IV bytes.

The 615-byte output is strict UTF-8. After outer whitespace normalization, it and the repository record are both 609 characters. Their only difference is index 384: the decrypted text has U+2019 and the record has U+0027. Replacing that one documented record glyph yields a complete match. Every cipher layer re-encrypts exactly to its input.

This replay reads a solved control, not Rev7. It validates the chosen historical primitives, CFB8 recurrence, key conventions, and representation steps. It does not identify any Rev7 layer or establish every possible historical frontend behavior.

## Reproduce

From this directory:

```sh
clang -shared -fPIC -O2 -Isource_build -Isource source/rc2.c -o source_build/librc2.so
clang -shared -fPIC -O2 -Isource_build -Isource source/loki97.c -o source_build/libloki97.so
clang -O2 -Isource_build -Isource -c source/rc2.c -o source_build/rc2.o
clang -O2 -Isource_build -Isource -c source/loki97.c -o source_build/loki97.o
clang++ -std=c++17 -O3 native_siblings.cpp source_build/rc2.o source_build/loki97.o -o native_siblings
python3 -B controls.py
```

`controls.py` refuses to overwrite `controls.json`. Recorded tools are Python 3.9.6 and Apple clang 21.0.0 on little-endian macOS arm64.

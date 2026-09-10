# Unified native ASCII plus five-punctuation controls

Identity: **ASTRA**. Target evaluated: **false**. No Rev7 file was read.

This isolated package extends the reviewed endpoint by exactly one complete UTF-8 sequence, U+2026 ellipsis (`E2 80 A6`). The complete endpoint is TAB, LF, CR, ASCII 32 through 126, and `E2 80 93`, `E2 80 94`, `E2 80 98`, `E2 80 99`, or `E2 80 A6`. A plaintext is terminal only in FSA state zero.

The six backends reuse previously reviewed conventions:

- AES-128: `Zombies` plus nine NUL bytes.
- Standard Blowfish: raw seven-byte `Zombies`.
- DES: `Zombies` plus one NUL byte.
- Blowfish compatibility: raw seven-byte key and word-wise byte reversal around standard Blowfish.
- RC2: unchanged pinned libmcrypt source with raw seven-byte key.
- Loki97: unchanged pinned source, selected length 16, with the library-equivalent 32-byte zeroed backing memory.

Every cipher uses CFB8 and an ASCII-zero IV at its block size. Key setup occurs once per oracle or native cipher object.

## Endpoint controls

The exact 149-byte plaintext recovered by the pinned-source Rev9 control has SHA-256 `10d049e3b2c0d9840e52e746bc45a9ce0590ec3939a16ccdc258fffa72d1b197`. The prior four-sequence endpoint rejects it at its original `E2 80 A6`; this five-sequence endpoint accepts the complete bytes. Isolated endings `E2` and `E2 80` remain nonterminal, and `E2 80 A5` is rejected.

A mixed plant contains every registered multibyte sequence and leaves four display-symbol mappings unknown. For every backend, the C++ search and Python `prototype.backtrack` callback match every statistic, factorial weight, mapping, and full plaintext across all 24 naive permutations, including the planted mapping.

A separate fixture containing all 256 byte values plus an ASCII suffix verifies native CFB8 encryption and decryption byte-for-byte against the Python implementation for all six backends. Full-sixteen-symbol fixtures compare exact native/Python counters and survivors at fresh 250,000- and 1,000,000-node caps for each backend. All twelve capped fixtures stop exactly at their cap and remain incomplete. They establish deterministic implementation parity and cap semantics; they make no completeness or target claim.

## Historical source

The copied RC2 and Loki97 source files are unchanged from [Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`](https://github.com/Distrotech/libmcrypt/tree/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms). Their exact hashes and the pinned license are in `controls.json`. The Python control uses separately compiled shared objects, while the native engine links separately compiled object files. AES, Blowfish, Blowfish compatibility, and DES use the reviewed OpenSSL 3.6.3 or PyCryptodome primitives.

## Reproduce

From this directory:

```sh
clang -O2 -Isource_build -Isource -c source/rc2.c -o source_build/rc2.o
clang -O2 -Isource_build -Isource -c source/loki97.c -o source_build/loki97.o
clang -shared -fPIC -O2 -Isource_build -Isource source/rc2.c -o source_build/librc2.so
clang -shared -fPIC -O2 -Isource_build -Isource source/loki97.c -o source_build/libloki97.so
clang++ -std=c++17 -O3 -Wno-deprecated-declarations native_text5.cpp   source_build/rc2.o source_build/loki97.o -o native_text5   -I/opt/homebrew/Cellar/openssl@3/3.6.3/include   -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto   -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib
python3 -B controls.py
```

`controls.py` refuses an existing `controls.json`. The recorded environment is Python 3.9.6, Apple clang 21.0.0, OpenSSL 3.6.3, and little-endian macOS arm64. No target driver or target result is included; any Rev7 run requires separate review and authorization.

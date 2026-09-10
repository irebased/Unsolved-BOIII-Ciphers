# Native first-six byte-AMSCO controls (ASTRA)

This directory contains a synthetic-only native implementation of the accepted first-six-column theorem. It does not read Rev7 and contains no target driver or gate.

The executable supports odd widths 7 through 13 with an even number of complete AMSCO rows, both continuous one/two-byte starts, and four fixed-key eight-byte block backends:

- DES with `Zombies` plus one NUL byte;
- standard Blowfish with raw seven-byte `Zombies`;
- historical Blowfish compatibility with raw `Zombies`; and
- historical RC2 with raw `Zombies` and the source-defined effective 1024-bit setting.

For each ordered assignment of six distinct observed chunk ranks, it reconstructs the first nine natural bytes of every row, computes the ninth CFB8 plaintext byte, and rejects on the first byte outside A105. Every retained prefix includes its six ranks and all computed row-ninth bytes. Search order matches Python `itertools.permutations(range(width), 6)`.

The output records examined, rejected, retained, and unexamined prefix counts; block calls; `(width-6)!` weights; the exact `width!` partition; a survivor digest; and optionally every survivor. Retention is the default. `--count-only` is used only for synthetic timing fixtures whose recorded survivor count is zero. A future target must retain survivors.

An explicit `--evaluate` operation checks any supplied six-rank assignment and returns its complete row-ninth tuple when retained.

## Controls

The regeneration:

- compiles the unchanged pinned historical RC2 source in a temporary directory;
- checks 64 blocks per backend against independent PyCryptodome or compatibility-conjugation expressions;
- checks all 256 byte values through CFB8 encryption and decryption under two IVs;
- compares every native survivor tuple, plaintext-byte tuple, digest, counter, and weight with the accepted Python proof for all width-7 and width-9 prefixes, both starts, and all four backends;
- includes positive and rejected prefixes in every complete grid;
- checks the first 4,096 width-13 prefixes for each backend and start;
- evaluates the separate true planted width-13 assignment natively and matches all 28 computed plaintext bytes;
- checks cap and unexamined-weight accounting; and
- rejects six malformed invocations.

Default verification is standard-library only. It checks source and evidence pins plus ledger structure without requiring a compiler, PyCryptodome, or a native binary:

```sh
python3 -S -B research/byte_amsco/astra/prefix13/native/native_controls.py
```

Regeneration requires clang, OpenSSL development metadata through `pkg-config`, and PyCryptodome. It requires a new output path and refuses overwrites:

```sh
python3 -B research/byte_amsco/astra/prefix13/native/native_controls.py \
  --regenerate /tmp/prefix13-native-controls.json
```

The native binary and RC2 object are temporary build products. Their hashes document this host run and are not portable source identities.

## Runtime estimate

Eight one-million-prefix synthetic samples cover every backend and start. All benchmark prefixes rejected, so count-only lost no survivor payload. Rates ranged from about 5.57 million to 9.92 million prefixes per second. Linear scaling estimates approximately 5.21 native search seconds for the prospective 32 contexts, which contain 39,536,640 total prefixes. This excludes startup, orientation construction, result checks, and unexpected survivor handling.

No target runtime claim follows from this small synthetic benchmark.

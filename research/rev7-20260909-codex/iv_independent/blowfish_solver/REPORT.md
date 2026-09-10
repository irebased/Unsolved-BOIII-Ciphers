# Native Blowfish solver controls

**Identity:** ASTRA. The frozen ledger records `target_evaluated=false` and `rev7_read=false`.

This package controls the native global displayed-hex mapping search for standard Blowfish and the pinned historical Blowfish compatibility primitive. Both use the raw seven-byte key `Zombies`, CFB8, an eight-byte block, A105 relaxed byte pruning, and the strict five-sequence UTF-8 suffix automaton. These are synthetic controls only.

The native search is checked against a separately written exhaustive oracle over every one of the 4! mappings left after seeding twelve displayed symbols. Four 546-byte planted searches cover both ciphers and two arbitrary IVs; the exact mapping and plaintext-suffix sets agree and the planted mapping is recovered. Two deterministic random-ciphertext cases and two constructed prebound failures are real searches and reject all 24 mappings. Two cap-one controls verify incomplete-certificate accounting.

Primitive controls compare 64 native OpenSSL block results with PyCryptodome for standard Blowfish and with a temporary source-built historical libmcrypt C implementation for compatibility. The compatibility C results also equal the independent PyCryptodome word-conjugation construction. Four 546-byte CFB8 vectors cover both ciphers and both IVs, including roundtrip checks. The temporary historical library is rebuilt from hash-pinned vendored LGPL 2.1 source and deleted afterward.

The only native-source correction made during control generation is a CLI guard rejecting a zero node cap. The reviewed search body is unchanged; the original source is preserved at `drafts/pre_cli_cap_fix/native.cpp`.

The default command is read-only and requires no compiled artifact:

```text
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.py
```

Explicit regeneration writes only a new path and refuses an existing path:

```text
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.py --regenerate /tmp/blowfish-solver-controls.json
```

Regeneration requires Python, PyCryptodome, Clang, pkg-config, and OpenSSL development files. It compiles the native helper and historical compatibility source in a temporary directory. Machine-specific binary hashes are provenance for that run; the stable evidence is the hash-pinned source, exact commands, vectors, search rows, and ledger.

The certificate covers only the CFB8 suffix after the first eight bytes. Starting the suffix FSA in states {0,1,2} permits a UTF-8 sequence begun in the omitted prefix, while requiring terminal state 0 prevents a truncated ending. A surviving seeded control mapping is not a target solution or coverage claim.

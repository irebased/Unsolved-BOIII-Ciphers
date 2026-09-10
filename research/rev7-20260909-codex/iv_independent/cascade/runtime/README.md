# Seven-backend cascade runtime controls (ASTRA)

This synthetic-only package provides a common block/CFB8 interface for AES-128, DES, standard Blowfish, historical Blowfish compatibility, RC2, Twofish, and Loki97. It does not read or evaluate Rev7 and contains no target driver or gate.

`runtime.py` exposes a registry of objects with a key schedule constructed once, `encrypt_block`, CFB8 encrypt/decrypt, and `interval_decrypt`. For a known ciphertext interval `[L,R)`, `interval_decrypt` returns block size `b`, absolute offset `min(L+b,R)`, and exactly the decryptable plaintext bytes `[L+b,R)`. An empty result when the interval has at most `b` bytes is inconclusive.

Key conventions are fixed to the solved-family conventions: AES uses `Zombies` plus nine NUL bytes; DES uses `Zombies` plus one NUL; standard Blowfish, historical Blowfish compatibility, and RC2 use raw seven-byte `Zombies`; RC2 uses effective key length 1024; Twofish uses a 32-byte zero-backed buffer with declared/consumed length 16; Loki97 uses the same backing and declared length 16 while the pinned source reads all 32 backing bytes.

The three historical implementations are compiled only in a caller-owned temporary directory. Vendored source and shim hashes are checked first. No compiled library is part of the portable package. Source provenance and license copies are in `source/PROVENANCE.md`.

## Controls

The frozen ledger checks:

- source KATs for Twofish and Loki97;
- 32 actual-C Blowfish-compat blocks against the independently expressed standard-Blowfish word-reversal conjugation;
- every byte value through CFB8 encryption and decryption for all seven backends;
- AES/DES/Blowfish/RC2 CFB8 against both PyCryptodome `MODE_CFB(segment_size=8)` and a separate ECB-window recurrence;
- source-backed Twofish/Loki97 streams against exact prefixes of frozen solved-source control ledgers;
- five known-interval boundary cases per backend;
- one seven-layer direct-binary cascade under two unrelated IV suites, recovering the same suffix at the sum of block sizes; and
- a small 24-by-500-byte-per-backend timing sample, linearly scaled to 22,764 edges. The projection excludes graph, endpoint, and solver overhead and is not a runtime guarantee.

Portable read-only verification needs only the standard library:

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.py
```

Regeneration needs PyCryptodome and `clang`, builds sources in a temporary directory, and requires a new output path. It refuses to overwrite any file:

```sh
python3 -B research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.py \
  --regenerate /tmp/cascade-runtime-controls.json
```

Compiler version, temporary paths, binary hashes, and benchmark timings are environment records and can vary across regeneration. The frozen ledger hash is an audit coordinate; the portable default rehashes the vendored sources, both frozen prior-evidence ledgers, and the accepted direct/interval proof sources and ledgers. It also verifies the exact seven backend IDs and key conventions, all 35 interval ranges/offsets, and the unique seven-layer order and cumulative offsets. This is source and structural integrity verification, not a cryptographic replay or a claim of byte-identical rebuild output on every platform.

## Limits

These controls establish the named implementations, key conventions, CFB8 recurrence, and interval geometry on synthetic data. They do not scan any ciphertext, validate a future backend registry ordering, or prove endpoint acceptance for a target. Direct cascade interval propagation assumes binary layers at common alignment with no interposed encoding or transform; separate interval-extension controls cover the four registered byte transforms.

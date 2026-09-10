# Source provenance

The search geometry is implemented independently in `native.cpp` and pinned to the accepted Python proof and ledger in the parent `prefix13` directory.

DES and standard Blowfish use the OpenSSL low-level ECB primitives. The Blowfish compatibility wrapper uses the accepted per-32-bit-word reversal conjugation around standard Blowfish. Its historical-source equivalence and fixed raw-seven-byte key convention are inherited from the pinned `column_a/native/native_controls.json` evidence.

RC2 links the unchanged historical source:

- repository: https://github.com/Distrotech/libmcrypt
- commit: `3bd338e2f808e985f5b229a7642d48c26615993f`
- file: `research/byte_columnar/all_iv/column_a_rc2/source/rc2.c`
- SHA-256: `37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19`

The required source header, portability shims, license, accepted RC2 control ledger, prior three-backend native ledger, and seven-backend runtime ledger are hash-pinned in `native_controls.py`. Regeneration verifies every pin before compiling.

The controls compare DES, Blowfish, and RC2 CFB8 with PyCryptodome `MODE_CFB(segment_size=8)`. Blowfish compatibility is compared with a separately expressed word-conjugation ECB recurrence. These controls establish the native wrapper behavior used by this package; they do not establish a historical byte-AMSCO frontend.

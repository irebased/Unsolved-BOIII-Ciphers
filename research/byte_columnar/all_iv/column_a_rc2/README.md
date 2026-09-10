# Source-backed RC2 column-A controls

**Identity:** ASTRA  
**Target evaluated:** false

This package adapts the accepted rectangular FABLE column-A first-block certificate to historical RC2. It is synthetic-only: neither the Rev7 ciphertext nor a target driver is read or run.

For width `w > 8`, fixing the observed chunk ranks assigned to natural ciphertext columns 0 through 7 fixes `E_RC2(C[row*w:row*w+8])[0]`. Natural plaintext column 8 is therefore independent of the external IV. The engine intersects every unused observed rank whose ninth byte is in A105 across every row. An empty mask rejects `(w-8)!` complete column orders; a nonempty mask remains only an unresolved prefix/candidate set.

## Historical source and key

The unchanged RC2 implementation is [`modules/algorithms/rc2.c`](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/rc2.c) from Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`. Its companion `rc2.h` is genuinely empty. The preserved license is [`COPYING.LIB`](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/COPYING.LIB).

The source reports no discrete supported key sizes and a maximum of 128 bytes. Historical libmcrypt therefore passes the raw seven-byte key `Zombies` with declared length 7. `rc2.c` expands those seven bytes to its 128-byte schedule and omits effective-size reduction, corresponding to PyCryptodome ARC2 `effective_keylen=1024`. This describes effective-key-size handling; the input key itself remains seven bytes.

The C++ wrapper initializes the key schedule once per object. It copies each input block through aligned `uint16_t` storage before calling the unchanged source, avoiding an unaligned byte-pointer cast.

## Reproduction

The default command checks frozen source and ledger hashes using only the Python standard library:

```text
python3 -S -B research/byte_columnar/all_iv/column_a_rc2/controls.py
```

Regeneration requires PyCryptodome and Clang, builds all native artifacts in a temporary directory, and refuses an existing output:

```text
python3 -B research/byte_columnar/all_iv/column_a_rc2/controls.py --regenerate /new/path/controls.json
```

Portable build commands are recorded in the ledger. The temporary object, shared library, and executable hashes are machine evidence and are not publication inputs.

## Control scope

The ledger retains:

- the source embedded 128-byte-key KAT;
- 32 blocks for each of 5-, 7-, 16-, and 128-byte keys against independent PyCryptodome ARC2/1024;
- 32 fixed-`Zombies` native block vectors;
- complete 256-byte CFB8 streams and roundtrips under ASCII-zero and `0011223344556677` IVs;
- two complete `P(9,8)` planted scans with exact ordered Python/native prefix and candidate-set agreement;
- exact 1,000-prefix width-10, 13, and 14 comparisons containing multiple-candidate masks and unexamined-weight accounting;
- malformed-input rejection; and
- full native JSON for one-million-prefix width-13 and width-14 synthetic benchmarks.

These controls establish source, key, mode, geometry, enumerator, and accounting behavior. They do not test Rev7, recover an IV/order/plaintext, or establish other RC2 key lengths or effective-bit settings.

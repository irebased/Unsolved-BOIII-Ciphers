# Native rectangular columnar-A prefix engine

**Identity:** ASTRA

This directory contains a synthetic-only native implementation of the accepted rectangular FABLE columnar-A first-block certificate. It enumerates lexicographic assignments of observed chunk ranks to natural ciphertext columns 0 through 7. For every tuple it intersects unused-rank candidates for natural column 8 across all rows using DES, standard Blowfish, or historical Blowfish-compat block behavior with the frozen `Zombies` key conventions and A105 byte set.

An empty candidate mask rejects `(width-8)!` full orders. A nonempty mask records only the first-eight tuple and possible ninth ranks. It does not recover an order, plaintext, or IV. A bounded run partitions `width!` into rejected examined prefixes, unresolved examined prefixes, and unexamined prefixes.

Build with OpenSSL:

```text
clang++ -std=c++17 -O3 -Wno-deprecated-declarations $(pkg-config --cflags openssl) research/byte_columnar/all_iv/column_a/native/native.cpp $(pkg-config --libs openssl) -o research/byte_columnar/all_iv/column_a/native/native_search
```

Verify the frozen ledger without a compiled binary or crypto execution:

```text
python3 -B research/byte_columnar/all_iv/column_a/native/native_controls.py
```

Regeneration is explicit, refuses an existing destination, and requires `native_search`:

```text
python3 -B research/byte_columnar/all_iv/column_a/native/native_controls.py --regenerate /new/path/native_controls.json
```

The controls first pin and read the accepted proof ledger. They compare 96 fixed-key ECB vectors with independent PyCryptodome or temporarily compiled historical-C results; compare complete 256-byte CFB8 streams and roundtrips; perform complete width-9 native/Python comparisons; and compare exact ordered survivors and counters for 1,000-prefix width-10, 13, and 14 cases that deliberately contain multiple-candidate masks. Seven invalid inputs and exact factorial accounting are checked. One-million-prefix width-13 and width-14 samples measure bounded performance on a public synthetic 546-byte fixture.

The compatibility shared object is built in a temporary directory through the pinned helper. Its hash and invocation are machine-run evidence. The native binary SHA is also machine-specific. Portable provenance consists of the frozen source and helper hashes, commands, and independent control vectors. No Rev7 target is read or evaluated.

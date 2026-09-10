# Rectangular columnar-A all-IV first-block certificate

**Identity:** ASTRA

FABLE defines `order[rank] = natural_column`. The inverse uses `slots = inverse(order)`:

```
C[row*w + natural_column] = observed[slots[natural_column]*q + row]
```

The package vendors the two exact FABLE JavaScript files required by the fixture. Their hashes and issue-comment origins are recorded in `fable/PROVENANCE.md`. Those research artifacts carried no standalone license notice; the provenance file records that fact without inferring a license.

For CFB8 with an eight-byte block cipher and rectangular width `w > 8`, assign observed chunk ranks to the first eight natural columns. At position `row*w+8`, the CFB register is exactly natural ciphertext columns 0 through 7 of that row and contains no IV bytes.

For every unused observed rank `k`, intersect across all `q` rows:

```
observed[k*q + row] XOR E(C[row*w:row*w+8])[0] in A105
```

An empty candidate mask rejects every completion of that first-eight tuple, with weight `(w-8)!`. The `P(w,8)` first-eight tuples are disjoint and partition all `w!` orders. A surviving prefix remains unresolved and is not an order, IV, or plaintext.

`A105` is a relaxed necessary byte set: TAB, LF, CR, printable ASCII, and the byte components of the five registered UTF-8 punctuation sequences. It does not enforce UTF-8 sequence structure.

Controls include an exact live FABLE fixture, 18 deterministic randomized toy cases, explicit all-survive and all-reject toy cases, and six real DES, Blowfish, and Blowfish-compat plants under two IVs each. The planted true ninth rank is uniquely retained in every backend case.

The compatibility control no longer depends on a prebuilt shared library. During explicit regeneration it compiles the vendored hash-pinned libmcrypt `blowfish-compat.c` in a temporary directory, compares distinct C and PyCryptodome word-reversal implementations, and deletes the temporary artifact afterward. `compat_source/COPYING.LIB` is the upstream GNU LGPL 2.1 license; exact source URLs and provenance are in `compat_source/PROVENANCE.md`.

The default command is read-only. It checks the frozen ledger, source hashes, assertions, counts, and live vendored FABLE fixture without compiling or writing:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/column_a/controls.py
```

To regenerate controls, provide a new output path explicitly. Existing paths are refused:

```sh
python3 -B research/byte_columnar/all_iv/column_a/controls.py \
  --regenerate /tmp/column-a-controls.json
```

Regeneration requires Python, PyCryptodome, Node.js, and Clang. To inspect only the pinned compatibility sources:

```sh
python3 -B research/byte_columnar/all_iv/column_a/compat_source/build_compat.py --check-sources
```

The structural prefix counts are `P(13,8)=51,891,840` and `P(14,8)=121,080,960`. This Python package is a proof and control reference. It does not read or evaluate Rev7, and it is not the separate native target engine.

Finite limits: rectangular FABLE variant A, eight-byte CFB primitives, the fixed keys exercised by the controls, and the A105 necessary filter. Ragged layouts, other widths or block sizes, other keys/modes, and strict UTF-8 endpoint validation are outside this proof package.

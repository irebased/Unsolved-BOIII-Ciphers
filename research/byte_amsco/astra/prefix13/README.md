# Width-13 first-six byte-AMSCO proof (ASTRA)

This synthetic-only package proves a necessary filter for inverse byte-unit AMSCO at width 13 followed by eight-byte CFB8 decryption. It neither reads nor evaluates Rev7 and contains no target driver or gate.

For an odd width and an even number of complete rows, the one/two-byte cell pattern flips at each row boundary. Each pair of rows contributes three bytes to every natural column. With length 546 and width 13 there are 28 rows, so every observed column chunk contains 42 bytes regardless of the column order.

For natural column `c` and row `r`, the byte offset inside that column is:

```
3 * floor(r / 2) + (r mod 2) * (start if c is even else 3 - start)
```

The current cell size is `start` when `r+c` is even and `3-start` otherwise. The first six natural cells contain exactly nine bytes in every row. Assigning six distinct observed chunk ranks to natural columns zero through five therefore fixes that row's first eight natural ciphertext bytes and its ninth ciphertext byte.

For CFB8 after the first full block:

```
P[i] = C[i] XOR E_key(C[i-8:i])[0]
```

Thus the ninth byte of each row is independent of the external IV. If any of the 28 computed bytes is outside A105, no completion of those six assigned ranks can produce a plaintext wholly inside A105. The rejected prefix represents exactly `(13-6)! = 5,040` complete column orders. There are `P(13,6) = 1,235,520` six-rank assignments per start, orientation, and backend.

This is only a necessary byte-alphabet filter. A retained prefix is not a plaintext, full column order, UTF-8 validation, or solve.

## Controls

The production formula is compared with an independently materialized complete AMSCO inverse:

- width 7, four rows, every 5,040 order, both starts;
- width 9, two rows, every 362,880 order, both starts;
- exact survivor classification and factorial expansion under a deterministic toy block function;
- positive and rejected cases in every exhaustive toy grid;
- width 13 bounded exact computed-byte tuple comparisons for 1,025 assignments including the true plant;
- DES, standard Blowfish, historical Blowfish compatibility, and RC2;
- both starts and two unrelated IVs per backend;
- manual CFB8 encryption equal to the accepted runtime;
- the true assignment retains all 28 planted plaintext ninth bytes under both IVs.

Default verification uses only the standard library:

```sh
python3 -S -B research/byte_amsco/astra/prefix13/controls.py
```

Regeneration needs PyCryptodome and clang through the accepted runtime, requires a new path, and refuses overwrites:

```sh
python3 -B research/byte_amsco/astra/prefix13/controls.py \
  --regenerate /tmp/prefix13-controls.json
```

The package pins the accepted parent byte-AMSCO sources and ledger, accepted seven-backend runtime sources and ledger, and every vendored runtime source hash.

# Inert width-13 byte-AMSCO target driver (ASTRA)

No target experiment is authorized or performed by this package. The driver requires a future immutable gate containing the exact reviewed source and scope, followed by external preregistration and a separate root GO.

The proposed grid contains 32 contexts:

- four backends: DES, Blowfish, Blowfish compatibility, and RC2;
- both continuous byte-cell starts, 1/2 and 2/1;
- four canonical hexadecimal orientations;
- width 13 and length 546 only.

Each context enumerates all `P(13,6) = 1,235,520` ordered assignments of observed 42-byte chunk ranks to the first six natural AMSCO columns. There is no cap, resume, or count-only target mode. Every survivor retains its six-rank assignment and all 28 computed ninth plaintext bytes. A retained prefix leaves `7! = 5,040` full column orders unresolved. A cell closes only when every prefix rejects.

The full grid contains 39,536,640 prefix evaluations. Completion weights are asserted against `13!` independently in every cell; counts are not added as independent permutation evidence across cipher, start, or orientation contexts.

Before any target operation, the driver:

1. verifies the future gate and every frozen source/control hash;
2. hashes the canonical MDX without extracting ciphertext during selftest;
3. rebuilds the native executable and historical RC2 object in a temporary directory;
4. requires the exact accepted host binary and object hashes; and
5. refuses any existing atomic cell or combined result.

During an authorized run, every retained prefix is independently replayed with the accepted Python formula and backend reference. The replay verifies the exact assignment and computed-byte tuple. It does not recover an IV, full order, or full plaintext.

## Synthetic callback controls

`driver_controls.py` exercises the exact `execute_cell` path on two complete width-7 plants. The DES start-1 cell examined all 5,040 prefixes, retained 135, and rejected 4,905. The RC2 start-2 cell retained 145 and rejected 4,895. Every retained tuple and computed byte sequence was replayed independently.

Portable read-only verification:

```sh
python3 -S -B research/byte_amsco/astra/prefix13/native/target/driver_controls.py
```

Explicit regeneration to a new path:

```sh
python3 -B research/byte_amsco/astra/prefix13/native/target/driver_controls.py \
  --regenerate /tmp/prefix13-driver-controls.json
```

The regeneration needs clang, OpenSSL development metadata, and PyCryptodome. It does not read Rev7.

A future gate-only selftest command would be:

```sh
python3 -B research/byte_amsco/astra/prefix13/native/target/run_target.py --selftest
```

The target command must not be run until the reviewed gate, preregistration, and explicit GO exist.

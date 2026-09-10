# Registered RC2 column-A target driver

**Identity:** ASTRA  
**Status:** frozen preparation; target unrun at publication

This directory registers an exact eight-cell extension of the accepted column-A method:

- unchanged historical libmcrypt RC2 with raw seven-byte `Zombies`;
- the schedule behavior independently matched by PyCryptodome ARC2 `effective_keylen=1024`;
- CFB8 and every external eight-byte IV through the IV-independent natural-column-8 constraint;
- rectangular FABLE columnar-A at widths 13 and 14;
- forward, full-hex reverse, byte reverse, and per-byte nibble-swap orientations; and
- relaxed A105 as a necessary byte filter.

Each cell begins at a fresh root and examines all `P(width,8)` first-eight rank tuples. The exact eight-cell workload is 691,891,200 tuples. Empty masks reject `(width-8)!` complete orders. Every nonempty prefix and exact ninth-rank candidate set is retained, so a cell closes only after a complete scan with no survivor.

## Source build

`build_native.py` compiles the pinned unchanged `source/rc2.c` and the reviewed C++ enumerator into a caller-supplied empty directory. It refuses existing object or executable paths. A reproduction build matched the accepted controls exactly:

- object SHA-256: `022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e`
- executable SHA-256: `679844dc071cce779d86667f1b8e55c5175045840d7b47044312f28dfdfd4b3b`

A gated target run builds into a temporary directory, checks both hashes before extracting target text, records normalized compile commands and build hashes, and removes the executable afterward. No binary needs publication.

## Driver safeguards

`prepare_gate.py` creates a source-bound gate from this reviewed specification. Execution requires separate root GO after FABLE preregistration. The driver enforces the following checks:

- `--selftest` will hash the MDX bytes but will not extract, orient, or evaluate ciphertext;
- `--run-target` will refuse any existing combined result or atomic cell;
- each completed cell will be written atomically with the full native result, including every prefix/mask survivor and all factorial/unexamined counters;
- every survivor mask will be replayed with PyCryptodome ARC2/1024 and the frozen Python tuple evaluator;
- a complete zero-survivor cell will close; any cell with a survivor remains unresolved; and
- the final ledger will retain the gate, source, control, build, input-orientation, and per-cell hashes.

Verification and target commands, with the target command reserved for the separately announced GO:

```text
python3 -B research/byte_columnar/all_iv/column_a_rc2/target/run_target.py --selftest
python3 -B research/byte_columnar/all_iv/column_a_rc2/target/run_target.py --run-target
```

## Frozen source hashes

- `build_native.py`: `a9f65c9c4781844dc984bc6f03d9f473d7e7360d3f11ddf094531e8cfe884d43`
- `run_target.py`: `deea54124124bae750ba57a35ebed6c5770e4f861ed25ae3aed6a7c660b1ab9a`
- accepted `controls.json`: `7330bad3670745ef659dd597a3385ee06b7225b17eadb997a0e80519ac3abb9f`
- accepted `controls.py`: `c9c32b8a3e95699e42c6edd961928b85a51098a42e966639d85826b4650d4006`
- reviewed `native.cpp`: `3c634ea5fa32caa146c2a078f85abdbc98984675744e7ffcf1977355e455a1cd`

The gate builder and selftest hash the MDX without extracting ciphertext. This publication registers the experiment and contains no target result or recovered layer. Both helper and driver refuse existing owned outputs; binaries are built temporarily from published source.

# Ragged variant-B all-IV prefix controls

Identity: **ASTRA**. This directory contains synthetic controls only. It does not read or evaluate the Rev7 target.

For a byte string of length `n`, width `w`, `q = floor(n/w)`, and `r = n mod w`, FABLE variant B writes natural ciphertext as contiguous column chunks and emits rows while visiting columns in the candidate order. The first `q` emitted rows are full under both FABLE ragged conventions. Therefore, for each observed rank `j`:

```python
guaranteed = observed[j : q*w : w]
```

is exactly the first `q` bytes of one unavoidable natural ciphertext chunk. This statement is independent of which natural column occupies rank `j`, which columns receive the `r` tail bytes, and whether FABLE assigns those long columns first or last.

In CFB8, plaintext bytes at chunk-relative offsets 16 and later depend only on the preceding 16 ciphertext bytes and the fixed AES key. They do not depend on the external IV or any ciphertext before this chunk. The detector decrypts that suffix directly, starts the endpoint automaton from every possible boundary state `{0,1,2}`, and does not require state zero at the end of the guaranteed prefix.

If any unavoidable chunk rejects, every column order is impossible for every external IV. The same byte witness closes the first-long and last-long convention models in parallel; their factorial weights must not be added. If every inspected rank retains, the cell remains unresolved: no order, IV, plaintext, or full reconstruction has been recovered.

For the 546-byte case, widths 2 through 32 have `q > 16`. Width 32 exposes one IV-independent byte per chunk. Width 33 has `q = 16` and is unsupported by this predicate. The compressed ragged tail at observed offsets `q*w .. n-1` is intentionally ignored.

The accepted endpoint is TAB, LF, CR, printable ASCII, and exactly the UTF-8 sequences U+2013, U+2014, U+2018, U+2019, and U+2026. A chunk may start inside one of these sequences, hence the three starting states.

Controls include:

- a live exact comparison with FABLE's JavaScript mapping for ragged first/last fixtures;
- valid 546-byte plants under arbitrary IVs and both conventions;
- invariance under mutation of the ignored compressed tail;
- forced NUL at chunk-relative byte 16 while every other guaranteed prefix is preserved;
- exhaustive width 3–6 permutation checks under two IVs;
- the width 32 positive/negative boundary and width 33 refusal.

Run once in a clean output directory:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged/controls.py
```

The control runner refuses to overwrite `controls.json`. Remove or copy that output only when intentionally generating a new control snapshot. It requires Python, PyCryptodome, Node.js, and the pinned FABLE files at the paths recorded in `controls.json`.

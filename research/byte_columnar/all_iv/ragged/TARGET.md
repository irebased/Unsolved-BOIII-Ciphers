# Ragged variant-B all-IV target preregistration

Identity: **ASTRA**. Target evaluation has not run.

The registered grid contains 124 cells: widths 2 through 32 crossed with the four canonical orientations `forward`, `full_hex_reverse`, `byte_reverse`, and `nibble_swap`. Every cell uses AES-128 CFB8 with key `Zombies` followed by nine NUL bytes, variant B, and quantifies over every external 16-byte IV. Both FABLE ragged conventions are covered in each cell.

For `n=546`, `q=floor(n/w)>16` throughout this width range. Rank `j` exposes the convention-independent natural ciphertext prefix `observed[j:q*w:w]`. The driver checks ranks in ascending order and stops after the first prefix whose IV-independent suffix fails the endpoint automaton from all boundary states. It stores every rank actually examined, including each full guaranteed prefix, direct suffix, hashes, state result, and first failure.

A rejected unavoidable chunk certifies `w!` orders impossible for every external IV under the first-long convention and separately `w!` under the last-long convention. These are parallel model certificates and are not added. When `r=0`, the conventions are explicitly marked as aliases. If every rank retains, the cell is reported unresolved without inferring an order, IV, or plaintext.

The independent driver check re-extracts each examined prefix from the oriented bytes, recomputes its CFB8 suffix with an independent AES-ECB recurrence, compares that suffix to PyCryptodome CFB8 decryptions under two IVs, and runs a separate endpoint automaton. Orientation involutions reconstruct the canonical ciphertext exactly.

Eight width-13/14 contexts were covered by the prior rectangular stronger result. They are replayed as source regressions against its exact observed hashes, rejected ranks, prefixes, and suffixes. The other 116 width/orientation contexts are new.

Frozen hashes and the canonical MDX/ciphertext hashes are recorded in `target_gate.json`. The gate refuses source drift, missing controls, failed controls, or a changed prior ledger. The driver refuses an existing `target_results.json` and writes an atomic checkpoint after each cell.

Pre-run gate check:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged/run_target.py --selftest
```

Authorized target command after explicit GO:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged/run_target.py --run-target
```

Finite limits: this proves only the registered necessary-prefix exclusions. A retained cell remains unresolved. Widths 33 and above have no guaranteed byte after the 16-byte register at length 546. Variant A, other ciphers, keys, modes, transpositions, IV framing, and broader plaintext endpoints are outside scope.

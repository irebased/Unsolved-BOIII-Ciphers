# Ragged variant-B all-IV target results

Identity: **ASTRA**

The preregistered 124-cell evaluation completed. All 124 cells contain an unavoidable natural ciphertext chunk whose IV-independent suffix fails the registered five-sequence endpoint from every possible chunk-boundary state. There are **124 closed cells and 0 unresolved cells**.

The scope was AES-128 CFB8 with key `Zombies` plus nine NUL bytes, every external 16-byte IV, FABLE variant B, widths 2 through 32, both first-long and last-long ragged conventions, and four canonical orientations. Eight width-13/14 contexts repeat the prior rectangular stronger result as exact source regressions. The other **116 contexts are new**.

The driver inspected 132 rank prefixes:

- 120 cells rejected at observed rank 0;
- two cells rejected at rank 1;
- one cell rejected at rank 2;
- one cell rejected at rank 4.

Each cell stores every rank actually inspected, its full guaranteed ciphertext prefix `observed[j:q*w:w]`, the full IV-independent plaintext suffix, hashes, endpoint states, and the first failing byte. The last stored rank in every cell is the rejecting rank. No cell exhausted all ranks without a contradiction.

For each closed cell, the rejected unavoidable chunk certifies exactly `w!` orders impossible under the first-long convention and separately `w!` under the last-long convention. The two convention weights are parallel model certificates and are not added. In 32 rectangular cells, where `546 mod w = 0`, the two conventions are explicitly marked as aliases.

Independent post-run verification checked all 124 cells and all 132 stored chunks. It recomputed each suffix with a separate AES-ECB CFB8 recurrence, matched PyCryptodome CFB8 decryption under two different IVs, reran an independent endpoint automaton, verified each factorial certificate, checked the complete Cartesian cell set, and confirmed all eight prior-result regressions.

Artifacts and hashes:

- `target_results.json`: `0f48686f1235e2e808f1f023ad5eb25eb323c78bf611060785af590dc747f305`
- `target_gate.json`: `b5265210ae09a8acc0f3c7c91e47212977264fe062640703aca0b3668255b2f4`
- `run_target.py`: `75fdd4e092b33350388d30ef14bc1ab760e7ffa25bd3036a7b2496cad1cbcab4`
- accepted `core.py`: `5dba6b7a2d2d79dba15a9dee008e2a0b8ddd4798ea4bbecb8f4b7d2547b4e450`
- accepted `controls.json`: `9749cbeb8a875e152f9535d642bad81bd09ea0343a3a6dc723514ad23c87ca83`
- prior stronger result: `d45bdb13020a0e0fbb92a1c80417fb58107c96656a1280bc5d3139677c1f83b1`

Executed once:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged/run_target.py --run-target
```

Finite limits: this excludes the registered variant-B mappings for the fixed AES key and endpoint for every external IV. It does not cover variant A, widths 33 or greater, other keys, ciphers, modes, IV framing, transpositions, or broader plaintext endpoints.

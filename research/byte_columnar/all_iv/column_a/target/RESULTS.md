# Rectangular columnar-A every-IV target result

**Identity:** ASTRA

## Result

All 24 preregistered cells completed their exact finite enumeration. Every cell had zero surviving first-eight prefix/ninth-rank candidate sets.

The run examined and rejected all **2,075,673,600** registered `P(width,8)` prefixes. In each width-13 cell, the `(13-8)!` weight closes all `13! = 6,227,020,800` complete orders; in each width-14 cell, the `(14-8)!` weight closes all `14! = 87,178,291,200` complete orders. These are per-context order spaces, since cipher and orientation cells overlap as hypotheses and are not additive evidence. All 24 cells are closed and none is unresolved.

| Backend | Width | Orientation | Prefixes | Block calls | Candidate tests | Native seconds | Survivors |
|---|---:|---|---:|---:|---:|---:|---:|
| DES | 13 | forward | 51,891,840 | 160,716,777 | 439,870,604 | 12.4827 | 0 |
| DES | 13 | full-hex reverse | 51,891,840 | 159,476,071 | 439,859,707 | 12.4283 | 0 |
| DES | 13 | byte reverse | 51,891,840 | 158,304,536 | 439,847,778 | 12.4341 | 0 |
| DES | 13 | nibble swap | 51,891,840 | 159,424,652 | 439,866,137 | 12.4241 | 0 |
| DES | 14 | forward | 121,080,960 | 396,473,403 | 1,231,584,443 | 31.7329 | 0 |
| DES | 14 | full-hex reverse | 121,080,960 | 395,793,742 | 1,231,718,392 | 31.6282 | 0 |
| DES | 14 | byte reverse | 121,080,960 | 387,930,859 | 1,231,558,932 | 31.1040 | 0 |
| DES | 14 | nibble swap | 121,080,960 | 384,404,091 | 1,231,683,602 | 30.8721 | 0 |
| Blowfish | 13 | forward | 51,891,840 | 160,732,079 | 439,898,318 | 9.33846 | 0 |
| Blowfish | 13 | full-hex reverse | 51,891,840 | 159,498,396 | 439,889,046 | 9.31398 | 0 |
| Blowfish | 13 | byte reverse | 51,891,840 | 158,316,132 | 439,888,089 | 9.28492 | 0 |
| Blowfish | 13 | nibble swap | 51,891,840 | 159,422,925 | 439,899,049 | 9.32072 | 0 |
| Blowfish | 14 | forward | 121,080,960 | 396,488,931 | 1,231,664,052 | 24.0935 | 0 |
| Blowfish | 14 | full-hex reverse | 121,080,960 | 395,770,116 | 1,231,656,931 | 24.0485 | 0 |
| Blowfish | 14 | byte reverse | 121,080,960 | 387,961,829 | 1,231,667,348 | 23.7695 | 0 |
| Blowfish | 14 | nibble swap | 121,080,960 | 384,388,394 | 1,231,655,401 | 23.4581 | 0 |
| Blowfish-compat | 13 | forward | 51,891,840 | 160,715,136 | 439,890,975 | 10.0560 | 0 |
| Blowfish-compat | 13 | full-hex reverse | 51,891,840 | 159,512,226 | 439,912,197 | 10.0172 | 0 |
| Blowfish-compat | 13 | byte reverse | 51,891,840 | 158,308,913 | 439,862,894 | 10.0614 | 0 |
| Blowfish-compat | 13 | nibble swap | 51,891,840 | 159,426,123 | 439,880,780 | 10.0488 | 0 |
| Blowfish-compat | 14 | forward | 121,080,960 | 396,446,912 | 1,231,604,709 | 25.6712 | 0 |
| Blowfish-compat | 14 | full-hex reverse | 121,080,960 | 395,779,750 | 1,231,677,697 | 25.6934 | 0 |
| Blowfish-compat | 14 | byte reverse | 121,080,960 | 387,921,476 | 1,231,647,463 | 25.2190 | 0 |
| Blowfish-compat | 14 | nibble swap | 121,080,960 | 384,410,753 | 1,231,765,014 | 25.6375 | 0 |

Aggregate native search time was 450.13858 seconds and aggregate driver wall time was 450.24773 seconds. The engine made 6,607,624,222 block calls and 20,058,449,558 ninth-candidate tests.

## Exact model and conclusion

For rectangular FABLE columnar-A, the inverse places bytes as

```text
C[row*w+j] = observed[slots[j]*q+row]
```

For an 8-byte CFB primitive and `w > 8`, assigning observed chunk ranks to natural ciphertext columns 0 through 7 fixes the CFB8 keystream byte at natural column 8 independently of the external IV. The engine intersects every still-unused observed rank that makes this ninth plaintext byte fall in relaxed A105 across every row.

Within this model, zero candidates for every first-eight tuple excludes every complete column order for DES, standard Blowfish, and historical Blowfish-compat with the registered `Zombies` key conventions, widths 13 and 14, and four canonical hex orientations, for every external eight-byte IV.

This is a finite exclusion of the registered necessary condition. It does not exclude other columnar definitions, widths, ciphers, keys, modes, alphabets, transcription changes, or nonrectangular handling. It does not recover an IV or plaintext.

## Verification and certificates

Post-run verification checked:

- the exact ordered 24 cell identifiers and absence of extra or missing cell files;
- each observed-byte SHA against the canonical four orientations;
- the frozen gate, driver, source, control, helper, binary, MDX, and canonical-text hashes;
- complete `P(13,8)` or `P(14,8)` enumeration in every cell;
- rejected plus surviving prefixes, unexamined weights, and `(width-8)!` completion weights against `width!`;
- exact equality of every atomic cell file with its combined-ledger entry; and
- retained survivor arrays and replay counters, both empty in all cells.

The zero-survivor result is the output of the controlled native enumerator whose logic was validated against independent Python exhaustive and bounded controls before the target. There is no second independent 2.075-billion-prefix target search. The independent survivor replay path had no retained candidate on which to operate.

## Reproduction and artifacts

The preregistered command was run once from the repository root:

```text
python3 -B research/byte_columnar/all_iv/column_a/target/run_target.py --run-target
```

The completed ledger can be checked without PyCryptodome or the compiled binary:

```text
python3 -S -B research/byte_columnar/all_iv/column_a/target/verify_results.py
python3 -S -B research/byte_columnar/all_iv/column_a/target/verify_results.py --check-local-cells
```

This verifier replays source integrity, canonical orientations, cell identities, and finite accounting. It does not repeat the native prefix search. The optional flag also checks every atomic cell file against the combined ledger. The binary recorded in the gate is bound to the machine-build hash in the frozen native controls, while the local executable itself is not required.

Artifacts:

- `target_results.json`: 45,574 bytes, SHA-256 `7ecf4315867eb5cb9ebaa8b3a907fdb476245520ea0f4115063d0c9addb85617`
- `verify_results.py`: SHA-256 `30c69d7309cd1253e327c660101e63c1fc446550f26f3b340561be9d9e4c815c`
- `target_gate.json`: SHA-256 `81563be8c6c2c8b87c6afa2ec733d6e476a196bc6c5002dfce6c33cb8902021b`
- `run_target.py`: SHA-256 `de193398bb315e2315ace0e2538711d32a9e3543023a6ecf1fbbce9b9a61c7de`
- `native.cpp`: SHA-256 `960cdbaf643ca531728e2c6eeb337a5834842de9773c3a256319e9720bef1b07`
- `native_controls.py`: SHA-256 `a86afa2cb63c42e2304aae9750d8017e14ee558a9d2c1f2f7011c26ec9b69540`
- `native_controls.json`: SHA-256 `7b29daceb19899a6de3ad21954a0793513d324064c0bb169f66683f248ce5fb3`
- local tested `native_search`: SHA-256 `4ad339f8f5d88766317ef2b939c51d21628018635246bbaac45df8ed1b0218d4`

The gate and result ledger preserve all remaining source/control hashes, exact scope, keys, alphabet, counts, per-cell timings, counters, observed hashes, and certificates. The binary hash records machine evidence; portable source and build instructions are in the native control package.

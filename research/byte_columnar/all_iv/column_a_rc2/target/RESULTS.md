# RC2 rectangular columnar-A every-IV result

**Identity:** ASTRA

## Result

All eight preregistered RC2 cells completed their full finite enumeration. Every cell retained zero first-eight prefix/ninth-rank candidate sets.

The run examined and rejected all **691,891,200** registered `P(width,8)` prefixes. In each width-13 cell, `(13-8)!` completion weight closes all `13! = 6,227,020,800` column orders. In each width-14 cell, `(14-8)!` closes all `14! = 87,178,291,200` orders. These are per-orientation order spaces and are not additive evidence. All eight cells are closed with no unexamined weight.

| Width | Orientation | Prefixes | Block calls | Candidate tests | Native seconds | Survivors |
|---:|---|---:|---:|---:|---:|---:|
| 13 | forward | 51,891,840 | 160,714,670 | 439,874,994 | 15.9448 | 0 |
| 13 | full-hex reverse | 51,891,840 | 159,491,581 | 439,878,905 | 15.8833 | 0 |
| 13 | byte reverse | 51,891,840 | 158,342,261 | 439,918,379 | 15.7701 | 0 |
| 13 | nibble swap | 51,891,840 | 159,420,829 | 439,881,878 | 15.8529 | 0 |
| 14 | forward | 121,080,960 | 396,497,794 | 1,231,635,861 | 40.0559 | 0 |
| 14 | full-hex reverse | 121,080,960 | 395,777,391 | 1,231,661,192 | 40.0783 | 0 |
| 14 | byte reverse | 121,080,960 | 387,920,732 | 1,231,595,985 | 39.2424 | 0 |
| 14 | nibble swap | 121,080,960 | 384,384,232 | 1,231,656,399 | 39.0001 | 0 |

Aggregate native search time was 221.8278 seconds and aggregate per-cell driver wall time was 222.097426 seconds. The engine recorded 2,202,549,490 RC2 block calls and 6,686,103,593 ninth-rank candidate tests.

## Exact model and conclusion

The cipher primitive is unchanged historical libmcrypt RC2 with raw seven-byte key `Zombies`. Its schedule behavior corresponds to PyCryptodome ARC2 `effective_keylen=1024`. The mode is CFB8.

For rectangular FABLE columnar-A,

```text
C[row*w+j] = observed[slots[j]*q+row]
```

Assigning observed chunks to natural ciphertext columns 0 through 7 fixes `E_RC2(C[row*w:row*w+8])[0]`. The natural-column-8 plaintext byte is therefore independent of the external eight-byte IV. For each first-eight tuple, the engine intersects every unused observed rank whose ninth byte lies in relaxed A105 across every row.

Within this exact model, the empty candidate set for every tuple excludes every complete column order for widths 13 and 14, all four canonical hex orientations, and every external IV. This is a finite necessary-condition exclusion. It does not exclude other columnar definitions, widths, ciphers, keys, effective-bit settings, modes, alphabets, framing, or transcription changes, and it does not recover an IV or plaintext.

## Verification

Post-run verification checked the frozen gate and every published source/control/build hash; reconstructed all four canonical orientations; checked the exact ordered eight cell identifiers and their observed-byte hashes; replayed every `P(width,8)`, `(width-8)!`, `width!`, rejected, survivor, and unexamined accounting field; checked aggregate block-call and candidate-test aggregates; and optionally compared every atomic cell JSON object with its combined-ledger entry.

The zero-survivor result comes from the controlled native enumerator previously matched against independent Python exhaustive and bounded controls. The portable verifier replays integrity and accounting; it is not a second 691,891,200-prefix search. Because no survivor was retained, the independent ARC2/1024 target replay path had no candidate mask to evaluate.

Run the standard-library-only verifier without a compiled binary or PyCryptodome:

```text
python3 -S -B research/byte_columnar/all_iv/column_a_rc2/target/verify_results.py
python3 -S -B research/byte_columnar/all_iv/column_a_rc2/target/verify_results.py --check-local-cells
```

## Reproduction and artifacts

The frozen target command was invoked exactly once:

```text
python3 -B research/byte_columnar/all_iv/column_a_rc2/target/run_target.py --run-target
```

The driver rebuilt the native executable from pinned source in a temporary directory. Its object and executable hashes matched the accepted synthetic-control build, and no compiled binary is required for publication.

- `target_results.json`: 21,605 bytes, SHA-256 `8c8b94ed9def1daacfc04e25aa03f4c25a89568ab29072a6672c49dde766e9de`
- `verify_results.py`: SHA-256 `8eccd7daddc2670020535a7e53e40f7826bcda4fe32be3bccc08138fea37ac0d`
- `target_gate.json`: SHA-256 `191240f56bcdea2233fece19cfa5f429c4296463f2a081bba8899152b4de642b`
- `run_target.py`: SHA-256 `deea54124124bae750ba57a35ebed6c5770e4f861ed25ae3aed6a7c660b1ab9a`
- `build_native.py`: SHA-256 `a9f65c9c4781844dc984bc6f03d9f473d7e7360d3f11ddf094531e8cfe884d43`
- tested temporary executable: SHA-256 `679844dc071cce779d86667f1b8e55c5175045840d7b47044312f28dfdfd4b3b`
- accepted `controls.json`: SHA-256 `7330bad3670745ef659dd597a3385ee06b7225b17eadb997a0e80519ac3abb9f`
- reviewed `native.cpp`: SHA-256 `3c634ea5fa32caa146c2a078f85abdbc98984675744e7ffcf1977355e455a1cd`
- unchanged historical `source/rc2.c`: SHA-256 `37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19`

The gate and result ledger preserve the remaining source, license, proof, MDX, canonical-text, build-object, control, and target-document hashes, plus the exact key, alphabet, per-cell counters, timings, and certificates.

# All-IV lossy `2013`/`2014` DES target results

Identity: **ASTRA**

The preregistered four-context scan completed without reaching either cap. It retained no terminal plaintext suffixes. This result applies only to DES CFB8 with key `Zombies\0`, the literal source-equivalent lossy keys `2013`/`2014`, 655 natural ciphertext bytes, the four registered orientations, and printable ASCII bytes `0x20..0x7E` from plaintext offset 8. The original IV and first eight plaintext bytes remain unknown.

| Orientation | Accepted suffix states | DES block calls | Maximum live frontier per root | Latest natural byte reached |
|---|---:|---:|---:|---:|
| `forward` | 26,215 | 30,311 | 36 | 60 |
| `full_hex_reverse` | 36,705 | 40,801 | 60 | 84 |
| `byte_reverse` | 30,343 | 34,439 | 35 | 68 |
| `nibble_swap` | 21,223 | 25,319 | 60 | 102 |

All four contexts processed all 4,096 compatible `C[0:8]` registers: 4,096 roots started and completed, zero partial roots, and zero unexamined roots. Accepted-state arrays sum exactly to the stored totals. Across the grid there were 114,486 accepted suffix states and 130,870 DES block calls.

## Independent zero certificates

`verify_results.py` checks the gate, source artifacts, canonical MDX/dataset equality, ordered grid, root proof, counters, and accounting. It then performs a separately implemented complete negative prefix enumeration. That replay constructs the CrypTool emission indices locally, enumerates compatible ciphertext bytes before testing plaintext, and uses PyCryptodome DES ECB for the CFB8 recurrence. It advances each of the 4,096 roots only until its frontier becomes empty.

The replay reproduces every stored per-byte accepted count, total, block-call count, maximum live frontier, and initial-register digest. Its compact ledger records the empty-prefix histogram, latest roots, and a digest over all 4,096 root outcomes for each orientation. This is a second negative prefix computation; it does not search beyond empty frontiers or claim to recover the unknown IV-dependent prefix.

## Reproduction

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy2013_alliv_controls/target/verify_results.py
```

The authorized target command was executed once:

```sh
python3 -B research/rev7-20260909-codex/lossy2013_alliv_controls/target/run_target.py --run-target
```

## Hashes

- Gate: `dbea147677ad626163cc44a6e49445db65c0ae82cbcd38bd542080c435a988ea`
- Full result: `bbebe2a33edcdd11f335f2f8f6abc3377f4203e825702613d827128abf63862c`
- Independent verifier: `d44e7aebff5945abd6cfbbd40549afd22fc7ccd026f96c7febd3565431168795`
- Prefix-certificate ledger: `e194a07fecd25374d5809bd50435659ded7f54f5a16b13fcc3cb986ee0234abd`

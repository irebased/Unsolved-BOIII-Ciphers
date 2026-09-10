# ASTRA odd-period Bifid16 pilot result

The single preregistered run completed all 16 cells: **7 UNSAT, 6 SAT, and 3 UNKNOWN**. The seven UNSAT results exclude only their exact orientation and period under the arbitrary 4x4 Bifid square and the necessary condition that the first 128 decoded bytes belong to bag213. The three timeout results are unresolved. Each SAT result is only a bag-compatible prefix; all six complete decoded byte strings fail the full bag213 test, strict UTF-8, and the narrower exact endpoint test. No plaintext or square is claimed.

## Frozen scope

- Orientations: `forward`, full-symbol `reverse`, `byte_reverse`, `nibble_swap`.
- Odd periods: 3, 31, 99, 1091.
- Solver: Z3 4.15.3 QF_BV, arbitrary permutation of 16 symbols at 4x4 coordinates, no symmetry breaking.
- Constraint: first 128 plaintext bytes in bag213 (TAB/LF/CR, ASCII 32–126, continuation bytes 80–BF, and lead bytes C2–F4).
- Timeout: 10,000 ms independently per cell. A timeout is `UNKNOWN`, never a negative.
- `full_exact_endpoint` refers to TAB/LF/CR + ASCII 32–126 + the five E2 80 93/94/98/99/A6 sequences. It is not the separate 201-codepoint endpoint used by the even-period work.

## Cell results

| Cell | Status | Solver seconds | Diagnostic |
|---|---:|---:|---|
| `forward_p3` | UNSAT | 0.019658 | — |
| `forward_p31` | UNSAT | 0.021772 | — |
| `forward_p99` | UNKNOWN | 10.013609 |; reason=timeout |
| `forward_p1091` | UNKNOWN | 10.015604 |; reason=timeout |
| `reverse_p3` | UNSAT | 0.006678 | — |
| `reverse_p31` | SAT | 2.597989 |; full bag213=false, strict UTF-8=false, exact narrow endpoint=false |
| `reverse_p99` | SAT | 5.255414 |; full bag213=false, strict UTF-8=false, exact narrow endpoint=false |
| `reverse_p1091` | UNSAT | 0.024811 | — |
| `byte_reverse_p3` | SAT | 1.659085 |; full bag213=false, strict UTF-8=false, exact narrow endpoint=false |
| `byte_reverse_p31` | UNSAT | 0.010610 | — |
| `byte_reverse_p99` | SAT | 1.003207 |; full bag213=false, strict UTF-8=false, exact narrow endpoint=false |
| `byte_reverse_p1091` | UNSAT | 0.020986 | — |
| `nibble_swap_p3` | UNSAT | 0.018227 | — |
| `nibble_swap_p31` | SAT | 4.384579 |; full bag213=false, strict UTF-8=false, exact narrow endpoint=false |
| `nibble_swap_p99` | UNKNOWN | 10.019839 |; reason=timeout |
| `nibble_swap_p1091` | SAT | 6.502513 |; full bag213=false, strict UTF-8=false, exact narrow endpoint=false |

Total recorded solver time was 51.574580 seconds. All three UNKNOWN rows report Z3 `timeout`. Every SAT model retains the full square and 546-byte plaintext. The driver independently decoded and re-encrypted each using `symmetry_probe.py`.

## Verification and artifacts

The read-only verifier passed all 16 cells. It checked the gate and exact Cartesian ordering, reconstructed every oriented ciphertext and hash, decompressed each formula with a 10 MB bound, rebuilt the exact QF_BV formula without calling the solver, and required byte-identical SMT-LIB. It also independently recomputed all six retained SAT plaintexts and re-encryptions. This is formula, integrity, and retained-model verification; it is not a second target search.

- `target_results.json`: 22,826 bytes, SHA-256 `5ffb45b7191689e119bbb4e930f124eda5f78d8ddbb229085e9c522245c5a4a1`.
- 16 deterministic gzip SMT artifacts: 251,865 compressed bytes.
- `target_gate.json`: SHA-256 `fef5128cd5a7d80fb31a48fdfc479e215271b250d9e423d69cbb53021d0d6654`.
- `run_target.py`: SHA-256 `52972d35244709e87f2de69b6f760b9cdc2029e82d93af9789bfffe2c34bb3eb`.
- `verify_results.py`: SHA-256 `bd2d2a58d2493b1e87e19bf0ca9e12f795c4c1b7fb26bbaa58be1bbbba276375`.
- `driver_controls.json`: SHA-256 `f4a18cbc5cdc24246aa93f89f1bd88689392d410226c19fae1342338d4bf4cb4`.
- Parent QF_BV controls: SHA-256 `380c7e0573e7e541e19d66331847e5d71c2f8ee6bc735d6b8aa9dbf45ce311bb`.
- Independent parent audit: SHA-256 `d984d8c9ea8118e85d7f21bb226df28925392141bbf4af6d9f8e1951c6892aec`.
- Canonical normalized ciphertext identifier: SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`.

Reproduction commands from the repository root:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_pilot/run_target.py --run-target
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_pilot/verify_results.py
```

The first command was run exactly once after the reviewed gate and preregistration. It refuses an existing output.

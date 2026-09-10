# ASTRA odd Bifid16 full-bag follow-up result

All nine preregistered follow-up cells are **UNSAT** under the complete 546-byte bag213 necessary condition. There are no SAT models and no UNKNOWN/timeouts.

The earlier 128-byte pilot already excluded seven other cells. Prefix UNSAT implies full-bag UNSAT, so the two runs together exclude all 16 originally registered orientation/period cells under the full bag213 condition: seven inherited prefix exclusions plus nine direct full-bag exclusions, with no cell counted twice. This conclusion applies only to the four canonical orientations and periods 3, 31, 99, and 1091 with an arbitrary 4x4 Bifid square. It does not close other periods, transformations, alphabets, repairs, or cipher families.

## Frozen model

- Selected cells: exactly the nine non-UNSAT cells from prior result `5ffb45b7191689e119bbb4e930f124eda5f78d8ddbb229085e9c522245c5a4a1`.
- QF_BV arbitrary 4x4-square Bifid relation; no symmetry breaking.
- Necessary endpoint: every one of the 546 decoded bytes belongs to bag213: TAB/LF/CR, ASCII 32–126, bytes 80–BF, or bytes C2–F4.
- Solver timeout: 10,000 ms separately for every cell.
- Meaning of UNSAT: no square satisfies this broad byte-bag condition for that exact orientation and period.

## Direct follow-up cells

| Cell | Prior 128-byte status | Full-bag status | Solver seconds |
|---|---:|---:|---:|
| `forward_p99` | UNKNOWN | UNSAT | 0.049802 |
| `forward_p1091` | UNKNOWN | UNSAT | 0.050806 |
| `reverse_p31` | SAT | UNSAT | 0.057293 |
| `reverse_p99` | SAT | UNSAT | 0.056466 |
| `byte_reverse_p3` | SAT | UNSAT | 0.058767 |
| `byte_reverse_p99` | SAT | UNSAT | 0.053492 |
| `nibble_swap_p31` | SAT | UNSAT | 0.895025 |
| `nibble_swap_p99` | UNKNOWN | UNSAT | 0.049550 |
| `nibble_swap_p1091` | SAT | UNSAT | 0.051308 |

The recorded solver calls total 1.322509 seconds. The target process took roughly 8.7 seconds wall-clock from the tool session, so formula construction, SMT serialization/compression, input/gate checks, and result writing dominated the run rather than Z3 solve time.

## Verification and hashes

The read-only verifier passed all nine rows. It validated the gate, pinned prior result and source files, exact selected-cell ordering and prior statuses, reconstructed every oriented ciphertext, bounded-decompressed all nine SMT artifacts, and rebuilt each QF_BV formula byte-for-byte without invoking the solver. With no SAT rows, there were no retained plaintext models to replay. This is saved-result and formula verification, not a second search.

- `target_results.json`: 9,567 bytes, SHA-256 `3bbb8ccd756ea29082b2394108544601c79eb0fe19d2259b2c8ba732294225a3`.
- Nine deterministic gzip SMT artifacts: 578,855 compressed bytes.
- `target_gate.json`: SHA-256 `9fa88c99738acce0ad230699fa46ee29b71a9264ea660e0dace2c29b5970b1a2`.
- `run_target.py`: SHA-256 `cd6f5abdbd63862dcb8cb84131b454e8dd9a8da6a24677b2a9b6992045edc338`.
- `verify_results.py`: SHA-256 `37f657c01ed2ecefdf08e992da7c0a62725942e25e11c005f998a40c81ab46c0`.
- `driver_controls.json`: SHA-256 `2f463b69dfa83ea3b7469ca25085c67f498f9b74a438edd6ed1d21ff158845f7`.
- Parent QF_BV controls: SHA-256 `380c7e0573e7e541e19d66331847e5d71c2f8ee6bc735d6b8aa9dbf45ce311bb`.
- Independent parent audit: SHA-256 `d984d8c9ea8118e85d7f21bb226df28925392141bbf4af6d9f8e1951c6892aec`.
- Canonical normalized input: SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`.

Reproduction commands:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_fullbag/run_target.py --run-target
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_fullbag/verify_results.py
```

The target command was invoked exactly once after the reviewed gate and preregistration and refuses existing artifacts.

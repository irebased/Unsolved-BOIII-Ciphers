# ASTRA complete-period one-square Bifid16 result

The single registered completion run evaluated all 2,175 fresh cells. It returned **2,168 UNSAT, 7 UNKNOWN, and 0 SAT**. The seven UNKNOWN rows are exactly the seven even-period cells left unresolved by the earlier pair-invariant inventory:

- `forward_p562` — timeout after 10.015336 solver seconds
- `forward_p972` — timeout after 10.015326 solver seconds
- `reverse_p16` — timeout after 10.015185 solver seconds
- `reverse_p514` — timeout after 10.015727 solver seconds
- `byte_reverse_p16` — timeout after 10.012940 solver seconds
- `nibble_swap_p850` — timeout after 10.015396 solver seconds
- `nibble_swap_p972` — timeout after 10.012431 solver seconds

No odd-period cell remains unresolved in the finite grid. No square or plaintext was recovered.

## Exact finite coverage

The declared universe is one arbitrary 4x4 Bifid square, the canonical 1,092-symbol ciphertext, four canonical orientations, and periods 1 through 1,092, with all 546 decoded bytes required to belong to bag213. This gives 4,368 cells.

- The square-independent even-period pair invariant excludes 2,177 cells.
- The odd pilot and full-bag follow-up exclude 16 disjoint cells.
- This completion run excludes 2,168 of the remaining 2,175 cells and leaves the seven timeout rows above unresolved.
- Union: **4,361 excluded and 7 unresolved**, with each of the 4,368 cells counted once.

Period 1,092 is the whole-message block and was already excluded by the even invariant. Every nominal period at or above 1,092 produces that same actual block, so the whole-block proof covers those equivalent nominal periods without multiplying them.

This is finite coverage only for the fixed one-square 4x4 Bifid definition and full bag213 necessary condition. It does not close two-square/Four-square variants, other transformations or alphabets, altered ciphertext, or other classical ciphers. UNSAT is not an English-language score. UNKNOWN is not a candidate or a negative.

## Execution evidence

The target ran once in session `22147`, with durable per-cell JSONL and atomic status updates. It completed all 2,175 cells in 3861.137043 wall seconds; recorded solver calls total 601.635566 seconds. There were no SAT outputs requiring model replay.

The full verification-only process ran once in session `86488` (PID 11097 observed externally) and exited 0. It rebuilt and byte-compared all 2,175 QF_BV formulas without invoking the solver, reconstructed every oriented input/hash, re-derived the exact prior-evidence subtraction, and checked the checkpoint/result/status identity.

Artifacts:

- `target_results.json`: 1,512,688 bytes, SHA-256 `736a34aed38826a8c1a1bf5e4fcd24d6f4aad817a435f2e09384fe493d4d35d6`.
- `checkpoint.jsonl`: 1,175,842 bytes, SHA-256 `67a5eeaf6d94329726243fcee9f8c49665bc4d10623f30a830c88ea86b37395d`.
- `status.json`: SHA-256 `8121d83592c85a890e12382d3fe81530dbdcf0dd0409c0cb78542384db7fd20d`.
- 2,175 `smt/*.smt2.gz` files: 135,693,674 bytes total.
- `target_gate.json`: SHA-256 `dba3f6a962392cd4bdcacb7b81bfd459f9b27387dc36b87d5bdddd0791f43ff2`.
- `run_target.py`: SHA-256 `6dd45ffb0d2a5825f9388b363bc2c97bbb799bc16a1a24587884455e95ffce56`.
- `verify_results.py`: SHA-256 `d070482f30750a9f58eece9d3caaaad294255d0dd8281ca58dda750b28312ef5`.
- `verification.json`: SHA-256 `58ddd2f79f9227e288b2982644ba24ea908158745e14b98efddfe7d1d6819b6d`.
- Synthetic driver-control ledger: SHA-256 `c9d7c595ac073b110262091dbe076fee0a28db294fc3550d86aa192b649e34da`.
- Canonical normalized ciphertext: SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`.

Reproduction commands:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_periods/run_target.py --run-target
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_periods/verify_results.py
```

The target driver refuses existing target, temporary, checkpoint, status, or formula artifacts. The completed target must not be rerun to verify it; use the second command.

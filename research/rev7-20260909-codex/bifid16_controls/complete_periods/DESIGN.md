# ASTRA complete-period Bifid16 driver design (inert)

This package defines the remaining finite grid for one arbitrary 4x4 square, canonical 1,092-symbol Rev7 input, four canonical orientations, periods 1 through 1,092, and the complete 546-byte bag213 necessary condition. It has no target gate and has not run fresh cells.

## Exact evidence subtraction

The universe has 4 × 1,092 = 4,368 cells. The pinned even-period invariant ledger excludes 2,177 cells at bound213 and leaves seven: forward 562/972, full-hex-reverse 16/514, byte-reverse 16, and nibble-swap 850/972. The driver explicitly normalizes `full_hex_reverse` to `reverse`. The pinned odd pilot/full-bag ledgers exclude 16 disjoint odd cells. Subtracting the exact union leaves 2,175 fresh cells: 2,168 odd and the seven even residuals. Period 1 is included. Period 1,092 already represents the whole-message block and the existing invariant excludes it; nominal periods at or above 1,092 have that same actual single block, so they are not multiplied.

## Execution contract

Each fresh cell uses the frozen QF_BV arbitrary-square relation, no symmetry break, full bag213, and an independent 10,000 ms timeout. UNSAT is a necessary-condition exclusion for that exact cell. SAT is bag compatibility only and retains the complete square/plaintext plus independent concrete decode/re-encryption and UTF-8 diagnostics. UNKNOWN is unresolved. No heuristic status becomes negative.

A future authorized run refuses any existing final, temporary, checkpoint, status, or formula artifact. After each cell it appends and `fsync`s compact JSONL and atomically updates status. It prints progress every 16 cells. A partial job remains explicitly incomplete and is not accepted as family coverage; this driver does not silently resume or restart it. Every cell retains deterministic gzip SMT-LIB locally. The final verifier binds all 2,175 inputs/formulas/models and requires the complete JSONL/result/status identity.

The nine-cell full-bag run took roughly 8.7 seconds wall time, while its solvers totaled 1.32 seconds. A simple optimistic projection is therefore about 35 minutes. The strict solver-only ceiling is 21,750 seconds (6.04 hours), with formula construction/compression overhead plausibly taking the bounded run toward roughly 6.5 hours. These are planning estimates, not measured target runtime.

`driver_controls.py` uses only fixed-square synthetic data. It dispatches all four orientations across periods 1, 3, 16, and 31 with varied final blocks, verifies allowed plants as SAT, and verifies an otherwise identical final `FF` byte as full-bag UNSAT. No target gate or execution is authorized by these controls.

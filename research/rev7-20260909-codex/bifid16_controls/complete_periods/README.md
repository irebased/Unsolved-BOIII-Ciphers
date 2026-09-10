# Complete-period one-square Bifid16 inventory

Identity: ASTRA. Rev7 is unsolved. This publication contains the frozen source, controls and gate for an active run; it does not claim that the full target inventory has completed or that the cipher family is excluded.

The driver covers the 2,175 cells left after the previously published evidence: 2,168 odd-period cells and seven even-period cells unresolved under the broader 213-byte union. Each cell uses the whole 546-byte message, an arbitrary fixed 4×4 square and a 10-second solver timeout. The full declared universe is four orientations and periods 1 through 1,092. The historical pre-run design is preserved in DESIGN.md; target_gate.json records the subsequent authorization and exact source hashes.

The source package uses the runtime and restoration instructions in [SMT_REPRODUCE.md](../SMT_REPRODUCE.md). The registered runtime is Python 3.9.6 with z3-solver 4.15.3.0 on macOS ARM64; its package, native library, source and license provenance are pinned there. The older even-period ledger is distributed through a lossless transport. In a clean clone, restore that file before running the completion verifier:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/even_target/pack_results.py --restore research/rev7-20260909-codex/bifid16_controls/even_target/target_results.json
```

This restore command refuses an existing path. The helper's default invocation instead verifies an already restored file. The completion source checks all prior evidence hashes, its controlled model and runtime, and the exact set of fresh cell IDs.

The recorded target command is `python3 -B research/rev7-20260909-codex/bifid16_controls/complete_periods/run_target.py --run-target`. It refuses existing target artifacts; do not use it to resume or duplicate the active run. After the completed result and formula archive are available, the verification command is:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_periods/verify_results.py
```

The verifier binds every cell to the frozen input, reconstructs every SMT formula and compares it byte for byte, checks complete checkpoint/status agreement, and independently checks any retained SAT model. It does not repeat the target solver search. UNKNOWN remains unresolved.

The [coverage reconciliation](../COVERAGE_RECONCILIATION.md) explains the conditional accounting for the narrower 201-codepoint endpoint. Its 165-byte union is a strict subset of the solver's 213-byte union. All 2,184 even-period cells already fail the narrower bound, so a complete verified UNSAT result for every remaining odd cell would exclude the declared one-square family at that endpoint. This condition has not yet been established. It does not cover other square relations, cipher chains, alphabets, or all classical ciphers.

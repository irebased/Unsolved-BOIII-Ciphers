# Complete-period one-square Bifid16 evidence

Identity: ASTRA. Rev7 remains unsolved. The completed solver inventory and the subsequent rectangle proof exclude the registered direct one-square 4×4 Bifid construction for all positive periods, four canonical orientations, and the 213-byte necessary text bag. That bag contains every byte of well-formed UTF-8 when ASCII is restricted to TAB, LF, CR and printable ASCII. It is not an English-language ranking.

The completion run returned 2,168 UNSAT, seven UNKNOWN and no SAT. Its full verifier reconstructed all 2,175 formulas and exited 0; the exact receipt is `verification.json`. The seven UNKNOWN solver rows remain unchanged. A later independent [empty-rectangle proof](../even_rectangle_target/RESULTS.md) excludes precisely those seven cases without another solver call. See that report for the final broad-bag reconciliation. `RESULTS.md` preserves the original solver result; `FINAL_COVERAGE.md` preserves the earlier narrow-bag reconciliation.

The declared universe is four orientations × periods 1–1,092 = 4,368 cells. A nominal period at or above 1,092 produces the same whole-message block. The result does not cover odd-period distinct input/output squares, other pipeline placements, UTF-16, arbitrary binary intermediates, or all classical ciphers. The even-period evidence separately applies to the proved construction with two distinct fixed squares.

The frozen driver, gate, controls and historical pre-run design remain available. This README was first published while the run was active in commit `4beaa2122efd98666d13cdf0303fb8d3c5d8d447`; the current state is complete.

## Restore and verify

Follow [the complete archive instructions](../complete_transport/REPRODUCE.md). The archive restores all 2,175 original gzip formula files exactly and retains their original gzip and decompressed SMT hashes. It is 17 JSON parts with manifest SHA-256 `69858bbc8f1cef2161bcd5f760a364bc7f6312664fb6242a18116f66d594e01e`.

The full formula verifier also needs the pinned native Z3 runtime and earlier evidence described in [SMT_REPRODUCE.md](../SMT_REPRODUCE.md). The registered runtime is Python 3.9.6 with z3-solver 4.15.3.0 on macOS ARM64. The portable archive checks and rectangle proof use the Python standard library.

Do not rerun `run_target.py --run-target` to verify a completed result. It refuses existing artifacts. The verification-only command is:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_periods/verify_results.py
```

It reconstructs inputs and every formula, checks checkpoint/status/result agreement, and does not run another target solver search.

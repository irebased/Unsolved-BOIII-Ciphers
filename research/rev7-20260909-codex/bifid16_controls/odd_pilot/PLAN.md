# ASTRA odd-period Bifid16 pilot (inert)

This is a bounded pilot design. It has not read or evaluated Rev7 and has no authorized gate.

The registered grid would contain the four canonical hex orientations (`forward`, full-symbol `reverse`, `byte_reverse`, and per-byte `nibble_swap`) crossed with odd Bifid periods 3, 31, 99, and 1091. Each of the 16 cells uses the arbitrary 4x4-square QF_BV formulation, the broad 213-byte necessary bag, the first 128 decoded bytes, one 10,000 ms Z3 timeout, and no symmetry breaking.

Each solver formula is retained as deterministic gzip-compressed SMT-LIB. `unsat` excludes only that exact cell under the necessary first-128-byte bag condition. `sat` is compatibility, not plaintext: the driver independently decodes the complete 546-byte candidate, re-encrypts it, and reports prefix-bag, full-bag, strict UTF-8, and exact legacy-endpoint predicates. Here `full_exact_endpoint` means the narrow TAB/LF/CR + ASCII 32–126 + five UTF-8 punctuation endpoint from `bifid16.py`; it is not the separate 201-codepoint endpoint used by the even-period counting work. `unknown` is unresolved.

`driver_controls.py` fixes the complete square and checks one allowed synthetic plant is SAT and one fixture whose first byte is `FF` is UNSAT. This demonstrates status handling without an unknown-key search. `verify_results.py` is designed to recompute every retained SAT plaintext and exact re-encryption from a future saved result. It also reconstructs each QF_BV formula byte-for-byte from the gated canonical input and checks its bounded gzip artifact, without calling the solver or rerunning UNSAT/UNKNOWN searches.

Default preflight hashes the canonical MDX and dataset only. Target extraction is reachable solely through `--run-target` and additionally requires a reviewed `target_gate.json` with `authorized: true`, matching scope, driver hash, and source hashes. No such gate is part of this inert package.

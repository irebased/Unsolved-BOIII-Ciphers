# ASTRA odd Bifid16 full-bag follow-up (inert)

This follow-up has no authorized gate and has not extracted or evaluated Rev7. It selects exactly the nine non-UNSAT cells from the pinned 16-cell pilot: forward periods 99/1091; reverse 31/99; byte-reverse 3/99; and nibble-swap 31/99/1091. It does not repeat the seven prior UNSAT cells or introduce periods.

Each selected cell uses the same arbitrary 4x4 square QF_BV relation, bag213, no symmetry breaking, and a 10,000 ms timeout. The only changed constraint is the complete 546-byte bag instead of the first 128 bytes. UNSAT therefore excludes the exact selected cell under this necessary byte-bag condition. SAT remains byte-bag compatibility, not UTF-8 or plaintext. UNKNOWN remains unresolved.

The synthetic driver control fixes a square and encrypts a valid 546-byte plant. It proves that plant SAT, changes only the final plaintext byte to forbidden `FF`, proves the full constraint UNSAT, and proves the same modified fixture SAT when constrained only through byte 128. SAT controls are independently decoded and re-encrypted.

A future authorized run retains deterministic gzip SMT-LIB for all nine rows and full SAT square/plaintext records. The verifier reconstructs each formula byte-for-byte without invoking Z3 and independently decodes and re-encrypts every SAT result. The canonical MDX and dataset are hash-only during preflight; extraction requires `--run-target` plus a separately reviewed authorized gate.

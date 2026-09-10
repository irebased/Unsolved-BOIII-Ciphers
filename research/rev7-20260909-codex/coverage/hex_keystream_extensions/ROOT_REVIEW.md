# Root review of the OFB8 and key extension

Identity: ASTRA. No target run has occurred at this review.

Root inspected runtime.js, model.js, run_target.js, README.md, the Python reference, and the control dispatch. Controls passed in root tool chunk a75d19, exit0; driver preflight passed in3eb803, exit0. Controls ledger237a2a5f403ab33cde275c33dd664afceed267e389f6fd2b7662c8a7903d9c14. The run expands1560 four-new-key full-mode/stream labels plus1140 OFB8 labels, rather than repeating the earlier780 full-mode labels. Old cryptographic aliases may still overlap and are reported separately.

OFB8 uses the first byte of block encryption of the current register, then shifts that register and appends the emitted keystream byte. Actual pinned WASM ECB encryption is direction1/mode1. This is a fixed stream, with no ciphertext feedback. Tests cover36 independent256-byte PyCryptodome reference streams and6 captured actual historical-C vectors. Family-B per-base controls retain64-byte streams; these do not by themselves verify every byte of a future546-byte stream. Source recurrence, longer reference/planted cases, and cross-orientation equality supply additional checks. Family A has546-byte keystream control hashes.

The new assignment bound maximizes sum_a W[a,g(a)] over bijections g. Dynamic programming over used-image subsets is exact: layer r assigns precisely r source symbols, and each transition adds one previously unused image. The terminal full-mask optimum upper-bounds every actual plaintext ASCII count because W already relaxes low-nibble conditions. The recovered assignment is a feasibility witness for that objective; proving optimality additionally needs the recurrence or an independent recomputation. It is not established by the witness alone. The independent verifier will recompute the optimum where used.

Every above-threshold case must remain unresolved at75% unless another sound weighted upper bound decides it. A100%-ASCII CSP failure cannot substitute for a75% certificate. Empirical stream eligibility stays separate from source-supported block-mode recurrence, as in the preceding published package.

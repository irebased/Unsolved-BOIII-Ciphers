# Registered Blowfish all-IV target harness

**Identity:** ASTRA. This document records the frozen experiment specification and synthetic cost evidence. No target result is included. Execution requires the final gate, a FABLE announcement and explicit root GO.

The proposed finite grid has eight fresh cells: standard Blowfish and the pinned historical word-conjugated compatibility primitive, each under the four canonical orientations. Both use raw seven-byte `Zombies`, CFB8, an arbitrary external eight-byte IV, a global bijection from the sixteen displayed hexadecimal symbols to nibble values, A105 relaxed pruning, and a strict five-sequence suffix FSA initialized in states `{0,1,2}` and required to terminate in state zero. Each cell has a fresh one-billion accepted-DFS-entry cap.

A complete cell certifies all `16! = 20,922,789,888,000` mapping weight. A capped cell reports only eliminated and accepted terminal weight plus the uncovered remainder. Exact native solutions retain every mapping and suffix. The driver independently checks the greedy geometry, reconstructs ciphertext and displayed text, recomputes every suffix byte with PyCryptodome blocks, runs a separate strict FSA, and decrypts/re-encrypts under two arbitrary IVs. Standard Blowfish uses PyCryptodome CFB8; compatibility uses a separate PyCryptodome word-conjugation recurrence already tied to the historical C primitive by the frozen controls.

The synthetic benchmark uses one deterministic 546-byte full-unseeded display and exactly one million accepted DFS entries per backend. Its host rates estimate runtime only. It establishes no target behavior or completeness.

Read-only benchmark verification:

```text
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/benchmark.py
```

After root review, public preregistration, a final `target_gate.json`, and explicit GO, the proposed commands would be:

```text
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/run_target.py --selftest
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/run_target.py --run-target
```

The driver checkpoints after each cell and supports explicit `--resume` only when its frozen configuration matches. Other keys, block ciphers, modes, endpoints, mapping models, or transforms are outside this proposed scope.

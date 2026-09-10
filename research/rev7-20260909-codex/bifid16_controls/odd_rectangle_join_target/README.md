# ASTRA odd typed-rectangle join target wrapper

This package records the preparation and, if separately authorized later, the bounded result of joining the four typed high-nibble graphs for the **80 unresolved cells** in the accepted odd single-graph result. It does not alter or repeat the 2,184-cell parent experiment.

For a prospective cell, the wrapper decodes the saved 256-bit `RR`, `RC`, `CR`, and `CC` edge masks. In target mode it also reconstructs the canonical orientation and typed source indices through the accepted parent driver, checks every saved graph against that reconstruction, then calls `odd_rectangle_join.model.analyze` exactly once. The registered limits are 10,000 candidates during each RC/CR preprocessing list and 1,000,000 joined pairs per cell, at most 80,000,000 examined join pairs across the grid.

An exhaustive `unsat` result excludes the bag213 necessary condition for two arbitrary fixed 4x4 Bifid squares. A `sat` result supplies only a coordinate-avoidance witness and remains unresolved. Either preprocessing or join cap produces `incomplete`, also unresolved. The wrapper does not call SMT, decode text, rank plaintext, or claim that a coordinate witness is valid UTF-8.

`selection_controls.py` binds the exact ordered 80 IDs to the accepted parent result and verification receipt without extracting the canonical ciphertext. `driver_controls.py` exercises the same wrapper entry point on reduced exhaustive cases, six accepted full-length positive plants, a source-reachable `p=1` binary negative, and an actual join-cap path. The plants deliberately reach the registered preprocessing cap and retain their independently known coordinate witnesses; this tests that caps cannot become exclusions.

Preparation commands:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/selection_controls.py
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/driver_controls.py
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/preflight.py
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/run_target.py
```

The last command is hash-only and does not extract target text. `build_gate.py` refuses an existing output and exists for root to create `target_gate.json` only after reviewing the frozen source/control hashes and recording a public authorization reference. Historical preparation wording here remains accurate if result artifacts are added later.

# Single typed graph coordinate-avoidance filter

Identity: **ASTRA**. Target-free model and controls; no Rev7 input is read.

For a directed typed graph G, an absent coordinate requires a Cartesian rectangle A × B containing no edge. Each class has four symbols. A and B represent the two selected row/column classes of one arbitrary 4×4 cipher square.

For each of the C(16,4) = 1,820 choices of A, intersect the missing-neighbor sets of its symbols to obtain M. Then all members of B must lie in M.

- RC or CR: row and column classes intersect in exactly one symbol. Such B exists exactly when `|M ∩ A| >= 1` and `|M \ A| >= 3`.
- RR or CC: classes are equal or disjoint. Such B exists exactly when `A ⊆ M` or `|M \ A| >= 4`.

These tests are necessary and sufficient for **one graph considered alone**. Any two four-symbol sets intersecting once can extend to a full square: put their intersection at (0,0), their remaining members along row zero and column zero, then fill the remaining 3×3 cells arbitrarily. Equal/disjoint same-axis classes likewise extend to a full square. The control constructs such squares for every retained feasibility witness and evaluates their coordinate fibers directly.

An impossible result for any one typed graph proves that every cipher square emits every coordinate in that graph. Therefore no second output square can reserve a coordinate for an absent high-nibble symbol. This excludes a byte alphabet that omits every byte with one specified high nibble, such as bag213 omitting 0x10..0x1F. If every graph individually survives, the result is inconclusive: the graphs must share one cipher square and one ordered forbidden coordinate, so their independently constructed witnesses cannot be combined freely.

Controls enumerate all 65,536 directed graphs on a 2×2 square for each of RR/RC/CR/CC (262,144 graph/type cases). An independent oracle evaluates all 24 literal cipher squares and all four coordinates to construct exact possible coordinate fibers. Every bitmask-filter answer agrees, and every feasible witness is independently extended to a square and checked. Another 168 full 4×4 empty/complete/planted/random graph fixtures replay all 1,820 intersections by direct edge membership. The generator uses no Rev7 input and no solver.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_single_graph_filter/controls.py
```

The default command is read-only and reconstructs the stored ledger. `--regenerate NEW_PATH` writes only a previously absent path. Source hashes and identity are included in the ledger.

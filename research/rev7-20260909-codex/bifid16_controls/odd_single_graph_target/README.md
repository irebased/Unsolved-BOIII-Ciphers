# Odd-period single-typed-graph target driver

Identity: **ASTRA**. This package is inert pending a separately reviewed authorization gate. Its default command hashes canonical source files and prints the planned scope without extracting the ciphertext. No target result exists or is authorized by these files.

## Reviewed theorem

For one typed directed graph `G_XY`, absence of plaintext high nibble `1` requires an empty `A × B` rectangle. Each set has four ciphertext symbols. For `RC`/`CR`, the row and column classes intersect in exactly one symbol; for `RR`/`CC`, the classes are equal or disjoint. The accepted model enumerates all `C(16,4)=1,820` first classes and its cardinality tests are necessary and sufficient for one graph considered alone.

The witness constructor is complete: cross-axis sets with intersection one extend to a square by placing the shared symbol at their crossing and filling the remaining 3×3 positions; equal or disjoint same-axis sets occupy one or two classes and the rest of the square can be filled arbitrarily. Duplicate typed edges do not affect emptiness, so storing each graph as a 256-bit set is exact.

If any nonempty typed graph has no allowed rectangle, every ciphertext-coordinate square makes that graph emit all 16 coordinates. A second arbitrary output square therefore cannot place symbol `1` at an absent coordinate, excluding bag213 for that cell. If every graph is individually feasible, the cell remains unresolved: the four graph witnesses need not share one ciphertext square or one forbidden coordinate. The filter never combines independently chosen witnesses and makes no full UTF-8 or plaintext claim.

The parent controls exhaust all 262,144 graph/type cases for side two against literal-square enumeration, and replay all 1,820 first-set intersections for 168 side-four fixtures. Review found no omitted class geometry or witness case. Parent source and ledger hashes are embedded in the driver.

## Frozen proposed grid

- Four canonical involutions: `forward`, full nibble-string `reverse`, `byte_reverse`, and per-byte `nibble_swap`.
- Every odd Bifid period from 1 through 1091: 546 periods per orientation, 2,184 cells.
- Exactly 1,092 ciphertext symbols and 546 plaintext-byte high-nibble positions per cell.
- Two arbitrary fixed 4×4 squares, tested only through the necessary absence of high nibble `1` from bag213.

For each actual period block, the driver flattens source coordinates conceptually as `R(C0), C(C0), R(C1), C(C1), ...`. For plaintext symbol index `i`, its coordinate comes from flat entries `i` and `L+i`; only globally even output-symbol positions supply byte high nibbles. The saved per-cell source-index metadata digest covers type, both source indices, block start/length, and local index, including every short final block.

Each type stores its 256-bit graph, unique-edge count, count of surviving first classes, first witness when present, and a deterministic digest of all 1,820 intersection records. Empty types are explicitly `no_constraints`. An exclusion stores the complete-all-first-sets digest; this is a finite certificate produced by the controlled enumerator, not an independent solver proof.

`--verify` reconstructs every graph and all compact records with the frozen model. It also derives every source-index tuple independently using flat-index division/parity rather than calling the production metadata routine, and checks the complete Cartesian grid and aggregate counts. It intentionally does not repeat a second slow literal-square enumeration over every target graph; that independent evidence belongs to the exhaustive parent controls.

## Synthetic driver controls

Forty fixed 546-byte printable-ASCII plants cover periods 1, 3, 31, 99, and 1091; same and distinct arbitrary squares; and all four orientations. An independent concrete encoder/decoder roundtrips every plant. Production source indices exactly match the published generic typed-edge oracle. The actual coordinate of plaintext-square symbol `1` survives every nonempty planted graph, and every planted cell remains unresolved as required. A reachable binary period-1 negative sets `cipher[i]=(i//2)%16`. Its high positions cycle all 16 symbols, producing all 16 RC diagonal edges; every row/column class pair contains its unique shared-symbol diagonal edge. The fixture passes through `scan_cell`, rejects all 1,820 first classes, populates the exclusion certificate, and independent literal decryption under eight square pairs confirms all 16 high symbols. It is explicitly not a valid-text plant. A separate complete 256-edge RC graph remains labeled only as a direct parent-model extreme.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_single_graph_target/driver_controls.py
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_single_graph_target/run_target.py
```

The controls hash the canonical MDX and dataset bytes through the driver parent-pin check, but do not extract the target ciphertext or evaluate it. The second command is inert. `--run-target` refuses to proceed without `target_gate.json`, exact driver/dependency hashes, and an explicit authorization marker. Result and temporary-file paths must both be absent. `--verify` is available only after a result exists.

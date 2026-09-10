# Exact coupled typed-rectangle join

Identity: **ASTRA**. This package is target-free and reads no Revelation 7 data.

For a forbidden output coordinate `t=(u,v)`, let `A=Row(u)`, `D=Row(v)`, `C=Col(u)`, and `B=Col(v)` in the unknown cipher square. Avoiding `t` requires four simultaneous empty rectangles:

- RC edges omit `A × B`;
- CR edges omit `C × D`;
- RR edges omit `A × D`;
- CC edges omit `C × B`.

The join first enumerates exact feasible cross-axis pairs `(A,B)` and `(C,D)`: each set has four symbols, its row/column intersection has size one, and its typed rectangle is empty. It then enforces the coupled square geometry and the RR/CC rectangles.

For the diagonal orbit, `A=D` and `C=B`. For the off-diagonal orbit, `A` and `D` are disjoint, `C` and `B` are disjoint, and all four selected row/column crossings have size one. These conditions are sufficient. The constructor places the two selected rows and columns, assigns the two remaining members of each selected row/column to the remaining axes, and fills the exterior 2×2 cells. The analogous side-2 construction has no exterior in the off-diagonal case. Every returned witness is checked against all literal typed edges.

SAT proves only that one coordinate can be absent. It does not establish UTF-8 or text. UNSAT is emitted only after every feasible RC×CR pair is obstructed. For an exhaustive UNSAT result, the ledger retains exact candidate counts, obstruction counts, and a deterministic SHA-256 stream over every `[RC_index,CR_index,reason]` row. A join or preprocessing cap returns `incomplete` and never an exclusion.

## Controls

The independent reduced oracle evaluates the coordinate inequality literally for all 24 side-2 square mappings and all four coordinates. It agrees with the join on the exact twelve accepted coordinate-avoidance fixtures and eight additional deterministic mixed/random graphs. The first twelve edge hashes must equal the accepted ledger. Abstract diagonal/off-diagonal side-2 quadruples equal the 48 quadruples induced by exhaustive squares and coordinates, and every constructed completion passes the literal oracle.

Six accepted 546-byte ASCII plants at odd periods 3, 5, 31, 99, and 1091 are reconstructed byte-for-byte. Their plaintext round trips and accepted ciphertext/edge hashes are checked. Both the planted distinct-square mapping and the join-generated square satisfy an independent literal edge oracle. Complete RC and CR graphs give immediate exhaustive UNSAT controls. A deliberately tiny preprocessing cap on an empty graph returns INCOMPLETE before a join and returns no witness.

## Complexity and limits

For side 4, one cross-axis list can contain at most

```
C(16,4) × 4 × C(12,3) = 1,601,600
```

candidates, and the unfiltered Cartesian join can contain 2,565,122,560,000 pairs. The positive plants returned witnesses after roughly 12,000–328,000 examined joins, but that gives no bound for an UNSAT graph. The implementation accepts separate candidate-generation and join caps. Candidate-generation and join caps must be declared before a target run; actual candidate counts are retained, and a capped result remains incomplete.

The model covers the exact coupled absence-coordinate condition for fixed 4x4 square geometry. It makes no text claim, enumerates row/column class configurations and constructs a witness at representative coordinate (0,0) or (0,1), and does not profile or evaluate target graphs.

## Reproduction

Read-only ledger replay:

```sh
cd /path/to/repository
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join/controls.py
```

Generate at an absent path:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join/controls.py \
  --regenerate /tmp/odd-rectangle-join-controls.json
```

`cap_semantics.py` supplies two additional root controls: a capped CR candidate list and an actual capped join over a graph with an uncapped SAT witness. Both return incomplete without a witness. Run it directly to reconstruct `cap_semantics.json`; this control reads no target data.

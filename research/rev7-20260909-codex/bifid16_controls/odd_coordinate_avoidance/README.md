# Odd-period typed-coordinate avoidance controls

Identity: **ASTRA**. This package is target-free and does not read Revelation 7.

For every ciphertext symbol `s`, `k[s]` is its unknown position in a 4x4 cipher square, encoded as the 4-bit word `row || column`. All sixteen `k[s]` values are distinct, hence form a permutation of the sixteen coordinates. A separate free 4-bit value `t` represents the plaintext-square coordinate at which forbidden high nibble 1 would reside.

For a typed high-output-nibble edge `(a,b,XY)`, the model asserts

```
Concat(axis_X(k[a]), axis_Y(k[b])) != t
```

where each axis is two bits. The conjunction is exactly the statement that one coordinate `t` is absent from every observed high-nibble coordinate. This is necessary for the 213-byte UTF-8 scalar bag because that bag contains no byte `0x10..0x1F`. It deliberately omits inverse plaintext-square lookup and UTF-8 grammar. Therefore UNSAT excludes the registered two-fixed-square construction, while SAT only leaves the cheap necessary condition unresolved.

The primary model leaves `t` free, allowing distinct fixed cipher and plaintext squares. The explicitly separate one-square option adds `t == k[1]`. Neither mode applies symmetry breaking.

## Controls

`controls.py` performs exact exhaustive comparison on a reduced 2x2 analogue. For twelve deterministic empty, complete, planted, mixed-type, and random graphs, it enumerates all 24 square permutations and all four `t` values and requires exact equality with complete Z3 model enumeration. It repeats the comparison with `t == k[1]`. The controls include both SAT and UNSAT cases; one planted mixed graph has two free-`t` solutions and zero one-square solutions, showing that the two modes are not conflated.

Six independent 546-byte ASCII plants are encrypted through literal one-square and distinct-square Bifid constructions at odd periods 3, 5, 31, 99, and 1091. The controls check decryption, global high-nibble parity, final short blocks, accepted `odd_typed_rectangles` edge metadata, and literal coordinate reconstruction. All planted true mappings satisfy the free-coordinate model. Constant odd periods over 1,092 symbols reach RC/CR edges and may reach RR through an even final block; CC cannot arise in that fixed geometry, but it is exercised in the reduced arbitrary-segmentation controls and supported by the model.

Complete 256-pair RC and RR graphs independently map to all sixteen coordinate pairs for each tested permutation. Z3 checks UNSAT only after fixing a source mapping in these full-size graph controls; it does not establish the unknown-mapping theorem. The general unknown-mapping conclusion follows separately and directly because a square bijection gives four nonempty classes on each selected axis, so all symbol pairs realize their Cartesian product.

The ledger retains every generated SMT-LIB formula, formula hash and byte length, SAT witness, exact reduced solution count and digest, source/runtime pins, and measured control time. On this machine, planted full-size SAT checks took about 0.02–0.04 seconds each; source-fixed complete-graph UNSAT checks took about 0.01 seconds. These are mechanics controls, not an UNSAT performance estimate for a target graph. Solver cost for an unbound coupled graph remains data-dependent and unmeasured.

## Reproduction

Generate a new ledger at an absent path:

```sh
cd /path/to/repository
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_coordinate_avoidance/controls.py \
  --regenerate /tmp/odd-coordinate-controls.json
```

Read-only replay of the frozen ledger:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_coordinate_avoidance/controls.py
```

The replay reconstructs every formula and reruns the exhaustive and synthetic controls. Timing fields are excluded from deterministic equality; formulas, witnesses, statuses, counts, digests, and all other fields must match. Z3 4.15.3 is loaded from the isolated runtime. The controls pin the dependency manifest and license, the actual native `libz3.4.15.dylib`, and the imported `z3` initializer, solver API, core loader, type, and constant modules. Complete enumeration is asserted only after a final Z3 `unsat`; `unknown` or a limit is explicitly incomplete.

# Common coordinate-label symmetry for odd typed avoidance

Identity: **ASTRA**. This package is target-free and leaves the accepted coordinate-avoidance model unchanged.

Let a square position be `k[s] = (r,c)`. For any permutation `sigma` of the four coordinate labels, transform both axes together:

```
k'[s] = (sigma(r), sigma(c))
t'    = (sigma(u), sigma(v))
```

For every typed edge `(a,b,XY)`, the old coordinate `(axis_X(k[a]), axis_Y(k[b]))` equals `t` exactly when the transformed coordinate equals `t'`. Therefore every inequality is preserved. The map on the sixteen cells is bijective, so `Distinct(k)` is preserved. If the one-square option has `t = k[1]`, then `t' = k'[1]` as well.

The common action has two coordinate orbits: diagonal `(u,u)` and off-diagonal `(u,v), u != v`. A constructive `sigma` maps any diagonal coordinate to word 0 `(0,0)` and any off-diagonal coordinate to word 1 `(0,1)`. Thus the free-`t` coordinate-avoidance model is equisatisfiable after restricting `t` to `{0,1}`.

This proof uses one common `sigma` on both axes. It makes no claim for independent row and column relabeling, transposition, or arbitrary permutations of the sixteen cells. Additional model constraints may use the reduction only after their own invariance is proved.

## Controls

The reduced 2x2 control exhausts all 24 square mappings, four `t` values, both label permutations, four edge types, and all sixteen ordered symbol pairs: 12,288 relation checks. It separately checks preservation of `t = k[1]`.

The full control uses eight deterministic 4x4 mappings, every one of sixteen `t` values, all 24 label permutations, all four edge types, and all 256 ordered symbol pairs: 3,145,728 relation checks. It also constructs and verifies the representative permutation for every coordinate.

Finally, the source reconstructs the exact twelve accepted reduced coordinate-avoidance graphs. For both free-`t` and one-square modes, raw exhaustive solution existence agrees with a fresh Z3 model restricted to `t` word 0 or 1. The ledger records exact raw solution counts and hashes of the restricted SMT-LIB formulas.

## Reproduction

```sh
cd /path/to/repository
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_coordinate_symmetry/controls.py
```

To generate a ledger at a new path:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_coordinate_symmetry/controls.py \
  --regenerate /tmp/odd-coordinate-symmetry.json
```

The default command rebuilds every check and requires exact equality with the frozen ledger. It reads no Revelation 7 data and runs no target search.

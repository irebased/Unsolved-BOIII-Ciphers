# Odd-period single-typed-graph target result

Identity: **ASTRA**. The exact preregistered target ran once after the reviewed gate was created. The saved verifier then reconstructed every cell and exited successfully.

## Scope and result

The finite grid contains four canonical orientations and every odd Bifid period from 1 through 1091: 546 periods per orientation and 2,184 cells. Each cell treats the 1,092 displayed symbols as ciphertext symbols under an arbitrary fixed 4×4 ciphertext-coordinate square and allows a distinct arbitrary fixed 4×4 plaintext-output square.

The endpoint is only the bag213 necessary condition that plaintext byte high nibble `1` must be absent. For each actual period block, the driver extracts the `RR`, `RC`, `CR`, and `CC` graphs induced at the 546 global high-nibble positions. If any one nonempty graph has no source-square-compatible empty 4×4 rectangle, the cell is excluded.

- Excluded cells: **2,104**
- Unresolved cells: **80**
- RC-impossible cells: **2,011**
- CR-impossible cells: **1,115**
- RR-impossible cells: **0**
- CC-impossible cells: **0**

The per-type counts overlap and must not be added. Every cell is accounted for. Runtime was `16.287073135375977` seconds.

## Exact unresolved cells

- `forward` (19): p229, p367, p369, p371, p375, p377, p381, p383, p385, p387, p389, p401, p405, p407, p417, p419, p423, p425, p439
- `reverse` (19): p159, p365, p367, p369, p371, p373, p379, p381, p383, p385, p387, p391, p399, p403, p407, p409, p415, p477, p591
- `byte_reverse` (21): p365, p367, p369, p371, p373, p375, p379, p383, p385, p387, p389, p391, p397, p399, p401, p403, p405, p407, p413, p429, p481
- `nibble_swap` (21): p365, p367, p369, p371, p373, p375, p377, p381, p383, p385, p387, p389, p393, p401, p405, p407, p415, p419, p439, p449, p463

These 80 cells are unresolved, not candidates with recovered squares or plaintext. No SMT search or cross-type square-coupling test was automatically added.

## Evidence and verification

Each nonempty typed graph retains its exact 256-bit edge mask, unique-edge count, surviving-first-class count, first witness when one exists, and a SHA-256 digest over all 1,820 deterministic intersection records. Excluded graphs also retain the complete all-first-sets rejection certificate. Source-index metadata covers each block start, short final-block length, type, local high-nibble index, and both ciphertext source positions.

The read-only verifier:

- checks the complete ordered 2,184-cell Cartesian grid and all aggregate counts;
- independently derives source indices from flat-coordinate parity and division rather than calling the production metadata routine;
- reconstructs every graph from those indices;
- replays all 1,820 mask records through the accepted model and checks their digests;
- checks the frozen gate, canonical MDX/dataset hashes, driver, controls, and parent theorem artifacts.

It does not perform a second literal-square enumeration for every target graph. Independent model evidence comes from the parent controls: all 262,144 reduced graph/type cases and 168 full 4×4 fixtures.

## Reproduction

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_single_graph_target/run_target.py --verify
```

Artifacts:

- `run_target.py`: `3c7ba1c60150a000018da4a1b14d523a827f8ed6b9f2187be39e169135babe06`
- `driver_controls.py`: `d0f4b76c04de47a5676d6f39ddd22648c5510003b8d33e634e539e47b19035e1`
- `driver_controls.json`: `01c3f757977c2c97a34398499f5024a4fea8f61999811bc88ab5675a33c79b8f`
- `README.md`: `4a8897df9c778e4ead0d9a5cdea57f973951f227ed1be64aa46f39819558e350`
- `target_gate.json`: `d998ffd22f7c80ee2c588cb737543ecf54881bfa3435d836701e33cbc62de6e8`
- `target_results.json`: `1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d` (`6,480,237` bytes)
- `verification.json`: `5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952`

## Limits

This result uses only the absence of high nibble `1` from bag213. It does not enforce the rest of bag213, valid UTF-8, English, or complete plaintext recovery. A feasible graph does not construct globally compatible squares. The exclusion applies to the stated fixed two-square 4×4 Bifid model and exact odd periods/orientations; it does not cover changing squares, other fractionation rules, damaged ciphertext, or additional transformations.

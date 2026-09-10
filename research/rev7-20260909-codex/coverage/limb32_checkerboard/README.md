# Fixed-width 32-bit limb decimalization -> checkerboard controls

Identity: ASTRA. This package defines and tests a target-free representation hypothesis. It does not read or evaluate Rev7.

The existing record distinguishes whole-integer conversion from an untested fixed-size limb boundary. The proposed recovery path takes each oriented byte string in four-byte chunks, interprets each chunk as unsigned big- or little-endian, and writes every full chunk as exactly 10 decimal digits. The exact final two bytes are a 16-bit limb written as exactly five digits. It then optionally reverses limb order and optionally reverses the complete digit stream. No byte padding, decimal truncation, or lost-zero repair is introduced.

An ordinary two-header straddling checkerboard has 28 code cells: eight one-digit cells and twenty two-digit cells. The proposed finite screen covers all 45 header pairs and records complete token sequences, distinct-cell counts, and all 27/28-cell cases. The fixed Rev3 diagnostic separately uses headers 3 and 7 with `FKMCPDYEHBIGQROSAZLUTJNWVX`; it has 26 populated cells and rejects its two blanks. A capacity-compatible unknown 27/28-symbol board is not plaintext recovery. A later substitution search would need an explicit 28-symbol endpoint such as A-Z plus space and period and must remain heuristic unless enumerated exactly.

For 546 bytes the grid is 4 orientations x 2 limb endiannesses x 2 limb orders x 2 digit directions x 45 header pairs = 1,440 cells. Each digit stream is 136 x 10 + 5 = 1,365 digits. This path is distinct from the historically reported whole-integer base16-to-decimal checkerboard scan because fixed widths preserve and reset leading zeros at every limb boundary.

`controls.py` compares the production serializer with a separately written shift-based implementation over 88 parameterized byte fixtures, checks the parser against an independent scanner for all header pairs, explicitly exercises a 28-cell stream and dangling headers, and recovers the complete planted chain `HLIMBHHH -> 3070322313|03030 -> u32+u16 bytes` under all 32 serializer/orientation combinations.

Reproduce the frozen controls:

```sh
python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/controls.py
```

Generate only to a new path:

```sh
python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/controls.py --generate /tmp/limb32-controls.json
```

Evidence pins are checked against `coverage/REPORT.md`, the exact Rev3 replay, and the Rev3 MDX. The model is a deliberately bounded hypothesis, not evidence that the puzzle author used machine-word decimal serialization.

## Bounded plaintext-recovery stage

The exact target parser will retain all 1,440 rows and deduplicate their token sequences. It ranks complete equality patterns by token IoC, a substitution-invariant descriptive statistic, then sends only the first 20 stable rows to the controlled monoalphabetic annealer. Each selected stream gets four deterministic restarts of 6,000 swaps over `ABCDEFGHIJKLMNOPQRSTUVWXYZ .`. The measured 850-token synthetic benchmark projects 54.85 seconds for this stage on the control host. The long 568-character shuffled-board plant is recovered exactly. Because selection and annealing are heuristic, failure to produce coherent text excludes neither lower-IoC rows nor other assignments.

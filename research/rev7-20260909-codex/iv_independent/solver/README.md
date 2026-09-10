# IV-independent CFB8 global-hex solver feasibility

Identity: **ASTRA**. Synthetic controls only. Target evaluated: **false**; no Rev7 file is read.

For an eight-byte-block CFB8 cipher, every plaintext byte after the first block is independent of the original IV:

```text
P[i] = C[i] XOR E_key(C[i-8:i])[0], for i >= 8
```

When ciphertext nibbles are displayed through an unknown global 16-symbol bijection, byte `i` becomes testable as soon as every displayed symbol in its nine-byte ciphertext window is assigned. `solver.py` implements that necessary constraint for the already validated DES convention: key `Zombies` plus one NUL byte. It does not introduce an IV variable and does not make any claim about the first eight plaintext bytes.

## Constraint model

The early byte filter is deliberately necessary and permissive. It admits 105 byte values: the 98 allowed ASCII values TAB/LF/CR and 32..126, plus the seven component bytes `E2`, `80`, `93`, `94`, `98`, `99`, and `A6`. A complete mapping then checks the whole recovered suffix with the strict five-sequence FSA. Since the omitted first block could leave the FSA partway through a multibyte character, suffix validation begins with state set `{0,1,2}` and accepts only paths ending in state zero.

The assignment order depends only on displayed-symbol geometry. It chooses a window with minimum unique-symbol count, breaking ties by the number of windows contained in that symbol set and then by earliest suffix index. Anchor symbols are ordered by occurrence. Each remaining symbol greedily maximizes newly completed windows, then total window containment, then lower symbol index. The optimized DFS assigns each window to the depth where its last unseeded symbol becomes bound and evaluates it exactly once. Failed assignments charge `factorial(unassigned entries)` to the rejection certificate; accepted complete mappings contribute terminal weight one.

AES is intentionally absent. Its 16-byte feedback window produces a substantially larger first-constraint assignment space in the supplied geometry analysis, while the present task is a bounded DES feasibility check for the eight-byte relation.

## Independent controls

The plant uses arbitrary IV `80ff017ec355aa19` and deliberately nontext first-block bytes `ff00807f81fea500`. Its suffix contains ASCII plus all five registered punctuation sequences. The first eight bytes may be nontext because the solver constrains only `i >= 8`.

With twelve mapping entries seeded and four unknown, the optimized solver, a separate Python path that rescans every currently bound window after every assignment, and direct enumeration of all 24 remaining permutations retain the same single mapping and exact suffix bytes. Their factorial certificate is complete at 24.

A 546-byte, full-sixteen-symbol fixture compares the optimized and rescan implementations for an identical 250,000-node prefix. Every statistic and survivor agrees. Both stop exactly at the cap with zero survivors, certificate weight 1,412,669,880, and uncovered mapping weight 20,921,377,218,120. Optimized time was 5.9981 seconds; the intentionally simple rescan reference took 68.9504 seconds. This prefix demonstrates implementation parity and honest cap accounting, not completeness.

## Reproduce

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/iv_independent/solver
python3 -B controls.py
```

The driver refuses to overwrite `controls.json`. The frozen ledger retains the mapping, ciphertext/display/suffix hashes, assignment geometry, every statistic, full solution bytes, certificate weights, timings, algorithm description, and source hashes. This package does not expose a target driver; any target application requires a separately reviewed and preregistered scope.

# Ragged byte-column extension assessment

Identity: ASTRA. This is a design assessment only; no additional target cell was evaluated.

## Exact FABLE mapping

For length `n`, width `w`, `rows=ceil(n/w)`, and `r=n mod w`, when `r>0`, FABLE assigns `r` long columns of length `rows` and `w-r` short columns of length `rows-1`; when `r=0`, all `w` columns have length `rows=n/w`. Convention `first` makes natural columns `0..r-1` long; convention `last` makes `w-r..w-1` long. The `first` and `last` conventions are aliases when `r=0`.

Variant A writes the pre-transposition bytes into valid cells row-major, then emits columns contiguously in `order`. Variant B stores the pre-transposition bytes as natural-column chunks, then emits rows while visiting columns in `order`. These are the definitions in the frozen FABLE sources, not labels inferred from names.

The rectangular solver assigns the observed rank for each successive natural column. That works because equal observed chunks have known boundaries. It cannot be copied unchanged for ragged A: the start of observed rank `k` depends on how many earlier emitted columns were long. Ragged B has a related final-row dependency.

## Sound causal construction

Partition the permutation space by a bit pattern saying which observed ranks hold long columns. There are `C(w,r)` patterns. For one pattern, every observed chunk boundary and every last-row position is fixed.

Within a pattern, assign natural columns in their original order to unused compatible observed ranks:

- A exposes the next row-major ciphertext byte for each assignment, so CFB8/FSA state advances through the first row. Once every column is assigned, reconstruct and validate the remaining rows.
- B exposes the next complete natural-column ciphertext chunk, including its last-row byte when long, so CFB8/FSA advances by `rows` or `rows-1` bytes per assignment.

Each complete order belongs to exactly one pattern. A rejected partial assignment within a fixed pattern represents
`factorial(unassigned_long) * factorial(unassigned_short)` completions. Summing rejected and terminal weights across all patterns must equal

`C(w,r) * r! * (w-r)! = w!`.

This is the ragged certificate. Charging `factorial(all_unassigned)` inside one fixed type pattern would overcount and is incorrect. A cap must retain the completed weight from every visited pattern and label the remainder uncovered.

An alternative rank-order DFS can charge `factorial(all_unassigned)` directly, but it often cannot decrypt until the natural-column prefix happens to be assigned. The type-pattern construction should preserve substantially more of the rectangular causal pruning.

## Cell counts and priorities

For 546 bytes:

| Width | Remainder | Rows | Unique conventions |
|---:|---:|---:|---:|
| 2 | 0 | 273 | 1 |
| 3 | 0 | 182 | 1 |
| 4 | 2 | 137 | 2 |
| 5 | 1 | 110 | 2 |
| 6 | 0 | 91 | 1 |
| 7 | 0 | 78 | 1 |
| 8 | 2 | 69 | 2 |
| 9 | 6 | 61 | 2 |
| 10 | 6 | 55 | 2 |
| 11 | 7 | 50 | 2 |
| 12 | 6 | 46 | 2 |
| 13 | 0 | 42 | 1 |
| 14 | 0 | 39 | 1 |

Widths 2–14 therefore contain 20 distinct width/convention cases, or 160 AES cells after two variants and four orientations. The completed rectangular result accounts for 16 of them. Widths 9–12 are the clean next gap: four widths × two conventions × two variants × four orientations = 64 cells. FABLE's byte-level source exhausts widths 2–8; its separate symbol-level width-10 work is not byte-level coverage.

The 64 AES cells should be control-benchmarked before registration. Their maximum raw permutation space is `12!`, far below `14!`, and B exposes roughly 45–61 bytes when the next natural column is assigned. Those facts support feasibility, but target-dependent FSA survival and the type-pattern traversal order prevent a runtime guarantee. Preserve first/last as separate labels even if a particular orientation happens to yield equal counters.

Widths 2–8 are lower priority. FABLE already searched them with a text gate, though the new exact five-sequence UTF-8 endpoint is not identical. A unified five-sequence certificate would add 80 cells: four exact widths (2,3,6,7) plus three ragged widths (4,5,8) with two conventions, times two variants and four orientations. Do not mix these reruns into the 64-cell width-9–12 claim.

## Cipher extension

The permutation engine only needs a validated ECB-encrypt primitive to generate manual CFB8 keystream bytes. Search logic and certificate bookkeeping are cipher-independent, but every adapter needs a full-byte CFB8 equivalence control and an exact key-buffer convention.

A tight order is:

1. Complete AES widths 9–12 first using the existing accepted backend.
2. If synthetic ragged controls confirm comparable pruning, add the historically visible outer sibling ciphers DES, Blowfish-compat, and RC2 as separate registered passes. Rev9's display is outer DES, Rev8's is outer Blowfish-compat, and Rev5's is outer RC2.
3. Treat standard Blowfish, Loki97, and Twofish as a later tier. They appear in solved sibling chains, but Blowfish and Loki97 are inner Rev5 layers and Twofish is the inner Rev9 layer, so a transposition immediately before visible-cipher decryption has a weaker direct sibling analogue.

DES and standard Blowfish can reuse accepted 8-byte native ECB adapters. Blowfish-compat needs the already proved word-reversal conjugation around raw-key Blowfish. RC2, Loki97, and Twofish require the pinned sibling-source adapters and their recorded nontrivial key-buffer rules; they should not be approximated by padding a generic library key. Integrating one adapter is small code work, but freezing source provenance and independent CFB8 equivalence is the material control work.

Do not multiply widths by all modes or key corpora. Prefix causality here relies on CFB8, and the historical question is the missing byte-column width, not another general cipher grid.

## Variant-B fixed-key, unknown-IV suffix test

For AES CFB8, plaintext byte `i` depends on the IV only while `i<16`. After 16 ciphertext bytes, the shift register consists entirely of the preceding reconstructed ciphertext and the suffix keystream is IV-independent. Variant B exposes 39 bytes at width 14 or 42 bytes at width 13 as soon as natural column zero is assigned, so it reaches this boundary within the first chosen column.

A sound fixed-key relaxation can ignore plaintext bytes 0–15, initialize the endpoint automaton at byte 16 with the reachable state set `{0,1,2}`, and propagate all three states over the IV-independent suffix. State zero means a normal boundary, state one means the skipped prefix ended in `E2`, and state two means it ended in `E2 80`. The full suffix must still terminate in state zero. If every possible first-column assignment empties this state set, each rejection charges `(w-1)!` and the resulting `w!` certificate excludes every 16-byte IV for the fixed AES key in that variant/width/orientation. This is one symbolic IV cell, not `256^16` sampled cells.

A surviving suffix would only show that some automaton boundary state remains possible; it would still need an explicit IV solution and complete-prefix validation. The claim also assumes ordinary CFB8 with an external IV. It does not cover a prepended-IV framing that changes which 546 bytes belong to the transposition. This optimization is especially attractive for the already defined rectangular B widths 13/14; it should be controlled there before considering any wider grid.

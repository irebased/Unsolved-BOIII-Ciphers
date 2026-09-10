# Even-block Bifid square-independent target inventory

```json
{"identity":"ASTRA","status":"complete","target_evaluated":true}
```

The registered inventory evaluated 2,184 cells: all 546 even periods from 2 through 1092 across `forward`, `full_hex_reverse`, `byte_reverse`, and `nibble_swap`. Every cell contains 546 ordered ciphertext-symbol pairs. The result retains the complete 256-bin pair histogram and ordered-pair byte-stream SHA-256 for every cell.

All 2,184 cells have more than 165 distinct pairs. By the proved pair-bijection invariant, **no arbitrary one-square 4×4 Bifid square can decode any registered cell into the exact 201-codepoint endpoint**. The same conclusion applies to the explicitly proved two-fixed-square coordinate construction. It does not automatically cover other algorithms called two-square Bifid or Four-square.

Against the broader 213-byte union for all well-formed Unicode scalar UTF-8 with only TAB/LF/CR and printable ASCII allowed as single-byte characters, 2,177 cells are excluded and seven remain unresolved:

- `forward`: period 562 → 212; period 972 → 212
- `full_hex_reverse`: period 16 → 213; period 514 → 209
- `byte_reverse`: period 16 → 213
- `nibble_swap`: period 850 → 212; period 972 → 212

Equality with 213 does not exclude a cell. These seven are merely unresolved by the byte-union invariant; they are not candidate plaintexts.

Per orientation:

| Orientation | Min–max distinct pairs | Excluded at 165 | Excluded at 213 | Whole-message p=1092 |
|---|---:|---:|---:|---:|
| forward | 212–238 | 546/546 | 544/546 | 225 |
| full hex reverse | 209–238 | 546/546 | 544/546 | 225 |
| byte reverse | 213–239 | 546/546 | 545/546 | 225 |
| nibble swap | 212–239 | 546/546 | 544/546 | 225 |

Period 1092 represents every nominal period at or above the 1092-symbol message length, including odd nominal periods, because each produces the same single actual block of length 1092. No multiplicity was added for those equivalent periods. Odd periods below 1092 remain outside this invariant because they contain odd actual blocks.

The independent verifier is a verification-only replay of the target-derived counts (`target_evaluated=true`, `verification_only=true`, `new_target_search=false`) and does not import the target driver. For global plaintext-byte index `j`, it reconstructs the pair using

```
a = floor((2*j)/p)*p
L = min(p, N-a)
local = floor((2*j-a)/2)
pair = (C[a+local], C[a+L/2+local])
```

It re-extracts the canonical ciphertext independently from the pinned MDX and dataset, reconstructs all four orientations, checks all 1,192,464 pair values and 559,104 histogram bins, recomputes both UTF-8 byte unions from literal codepoints/Unicode scalars, and checks every ID, block partition, digest, classification, summary, and proof-source pin.

Run from the isolated repository root:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/even_target/verify_results.py
```

Artifacts:

- target driver SHA-256: `b86fdd8402319753eb0292e75b9f0712a1ed2044038761e5d7a23af30cd4ff85`
- target result SHA-256: `acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8` (7,464,776 bytes)
- independent verifier SHA-256: `547eccc6b2dc6b5ec808b857934e26af86ea209271fcac6fc2f11e16a4cb023a`
- verification ledger SHA-256: `72d6197a1a59ec959c31f4b0236fb51cdb17430c3947df7c21f50b56af7656f3`
- canonical normalized input SHA-256: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

This is a distinct-byte necessary-condition proof, not a square search or language score. It does not identify plaintext, constrain odd periods below 1092, or cover transforms that alter byte distinct-count after Bifid.

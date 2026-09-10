# Even-period empty-rectangle result and broad reconciliation

Identity: **ASTRA**.

The seven preregistered bag213 residuals are all excluded. Every directed-pair graph has maximum common missing-neighbor count **1** across all 1,820 four-symbol row sets. An admissible fixed square would require an empty 4x4 directed rectangle, so the exclusion threshold is 4. The frozen target result is 2,864,836 bytes with SHA-256 `eec0e9f643d3b5ae2498b85eee8b8999b9ce2a8d3d714b8db1e971a048bf8ce1`; its gate SHA-256 is `410a9040fd2a40715680fe613dcf9fdc2383a5b5154289ce10fc04f3acbdf20c`. The target driver’s independent slow verification of every 1,820-mask table passed.

| Orientation | Period | Distinct observed pairs | Maximum common missing count | Result |
|---|---:|---:|---:|---|
| forward | 562 | 212 | 1 | excluded bag213 |
| forward | 972 | 212 | 1 | excluded bag213 |
| reverse | 16 | 213 | 1 | excluded bag213 |
| reverse | 514 | 209 | 1 | excluded bag213 |
| byte reverse | 16 | 213 | 1 | excluded bag213 |
| nibble swap | 850 | 212 | 1 | excluded bag213 |
| nibble swap | 972 | 212 | 1 | excluded bag213 |

## Elementary certificate

The 213-byte necessary bag for valid UTF-8 scalar text permits ASCII only at TAB, LF, CR, and `0x20..0x7E`. It contains no byte `0x10..0x1F`, so output high nibble 1 is forbidden.

For fixed cipher and plaintext 4x4 squares `Sc` and `Sp`, the even-block pair map sends an observed pair `(a,b)` to a byte whose high nibble is `Sp^-1(row(Sc(a)), row(Sc(b)))`. The plaintext-square coordinate of symbol 1 selects a row `r` and column `c`. Avoiding high nibble 1 therefore requires the observed pair graph to omit `A x B`, where `A` is cipher-square row `r` and `B` is cipher-square row `c`; both have four symbols. Testing arbitrary four-sets `A` and `B` is a relaxation. Because these seven graphs have no empty 4x4 rectangle, no fixed `Sc,Sp` pair can satisfy the bag.

Together with the verified complete-period reconciliation (`reconciliation.json` SHA-256 `781a33597decf6f60dc0f101157dbe478d4f7d4c8f64f31eee1edd0489568b6c`, formula-verification receipt SHA-256 `58ddd2f79f9227e288b2982644ba24ea908158745e14b98efddfe7d1d6819b6d`), this closes **4,368/4,368** registered one-square cells under bag213: four orientations and periods 1 through 1,092. It also closes **2,184/2,184 even-period cells** for any ordered pair of fixed cipher and plaintext squares. Period 1,092 is the whole-message representative for every positive nominal period at or above 1,092 because all produce the same single block.

The claim covers a directly applied fixed 4x4 Bifid construction and a necessary byte bag for valid UTF-8 scalar text with the stated ASCII controls. It does not cover odd-period distinct-square constructions, UTF-16, Bifid at another pipeline layer, arbitrary binary intermediates, transforms beyond the four canonical orientations, or other classical cipher families. The bag test is not an English score and is not by itself a sufficient UTF-8 grammar.

## Reproduction

Read-only reconciliation:

```sh
cd /path/to/repository
python3 -B research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/reconcile_broad.py
```

The compact ledger is `broad_reconciliation.json`. It pins the prior complete result and verification receipt, the even-period proof and ledger, the rectangle controls, and the seven-cell source, gate, and result. It checks the exact seven IDs, all 1,820 stored rows per cell, maximum 1, input histograms, and accounting without invoking Z3 or starting a target search.

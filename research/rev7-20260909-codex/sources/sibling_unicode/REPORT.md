# Sibling Unicode inventory

<!-- identity: ASTRA -->

This generator parses JSON editorial plaintext and each MDX `## Plaintext` block separately. Wrapper-only pages are recorded as `present: false`; no solved flag is used.

Allowlist: ASCII TAB/LF/CR, U+0020–U+007E, and U+2013/U+2014/U+2018/U+2019.

| ID | JSON bytes | MDX bytes | JSON outside | MDX outside |
|---|---:|---:|---|---|
| rev1 | 28 | null | none | — |
| rev2 | 529 | 529 | none | none |
| rev3 | 61 | null | none | — |
| rev4 | 207 | 202 | none | none |
| rev5 | 609 | 611 | none | none |
| rev6 | 126 | 126 | none | none |
| rev7 | null | null | — | — |
| rev8 | 868 | 869 | none | none |
| rev9 | 148 | 148 | U+2026×1 | U+2026×1 |
| rev10 | 229 | 229 | none | none |
| rev11 | 568 | null | none | — |
| rev12 | 207 | 208 | none | none |
| rev13 | 339 | 341 | none | none |
| rev14 | 164 | 164 | none | none |

Notable outside-allowlist characters: JSON `rev9` has U+2026 once (`Everywhere my love…Everywhere.`). MDX `rev9` has the same U+2026 once. MDX `rev5` and `rev13` contain U+2019, which is allowed; JSON `rev5`/`rev13` use ASCII apostrophes. JSON `rev7` and MDX `rev7` have no plaintext block (`null`/absent).

The generator asserts the canonical JSON hash and all 14 MDX hashes before writing `inventory.json`.

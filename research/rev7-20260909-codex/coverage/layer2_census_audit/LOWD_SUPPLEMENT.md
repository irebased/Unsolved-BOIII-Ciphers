# D=71 residual membership supplement

Identity: **ASTRA**. Read-only review; no cipher was rerun.

Captured FABLE artifacts:

- `upstream/l2_lowD_check.js`, SHA-256 `227e6513d888602a3a2f60700e74c1f624101b71897c21cbb4358d1a2c110ee8`
- `upstream/l2_lowD_check.json`, SHA-256 `3e4253a5e2a53923a08a78b1fa8a00ccde227a415079ed293f400d8776f5e074`

The two evidence rows are exactly the two saved census rows with `D <= 71`, including their identifiers, parameters, lengths, hashes, and alias fields. The new script reruns those two decryptions and counts bytes outside the literal set `A-Z a-z 0-9 + / =` plus bytes `SPACE TAB LF CR VT FF`. Its saved evidence reports:

| row | length | D | bytes outside literal set | literal-set fraction |
| --- | ---: | ---: | ---: | ---: |
| `d3_rev7_0033` | 98 | 71 | 70 | 0.286 |
| `d3_rev7_0114` | 96 | 71 | 79 | 0.177 |

This rules out **direct** membership in that fixed 71-byte set for the two rerun outputs. The evidence file still retains counts and output hashes rather than output bytes, so this capture cannot independently recompute the membership counts without repeating the cipher calls.

It does not rule out an unknown bijective byte substitution before Base64 interpretation. Let `V` be the 71 distinct bytes in either output and `B` the declared 71-byte Base64-plus-formatting set. Any bijection from `V` to `B` extends to a permutation of all 256 byte values. Under that permutation, every observed byte belongs to `B`. This establishes only membership feasibility; Base64 placement, padding, whitespace, and decoding constraints would still need a separate exact test. Therefore the new nonmembership counts cannot be promoted to an arbitrary-substitution exclusion.

The named input `corpus_rev7/stageA_manifest.json` remains absent from the mirror. A filename search found no copy, and a content search for its recorded SHA-256 `826f6cf5bed8f682132f1f3eb6c89864739daeb1c80efff7ce5539ee7fa76256` found only the census source and summary. Input provenance remains recorded but not locally replayable from this capture.

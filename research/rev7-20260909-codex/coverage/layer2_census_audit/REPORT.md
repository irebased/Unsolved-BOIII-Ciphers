# Layer-two distinct-byte census source audit

Identity: **ASTRA**. This is a structural replay of frozen FABLE v2 artifacts. It does not rerun the ciphers.

## Captured evidence

- `upstream/l2census_v2.js`: SHA-256 `e2a3ec96909c8a4a6fcd8388ce76fbf58d57dee426eefd07bf9e5fb1239b0a8b`
- `upstream/l2census_rows.json`: SHA-256 `043a19052984429cea07bf7247fd5683e2dca9b917b1f1d4448c0d4c66673929`
- `upstream/l2census_summary.json`: SHA-256 `bfd8f04d67908076d340e669dbb19278d3f8a298503c0ae7e642942b57372bfb`

The source names `corpus_rev7/stageA_manifest.json` with SHA-256 `826f6cf5bed8f682132f1f3eb6c89864739daeb1c80efff7ce5539ee7fa76256`, but that input manifest was not supplied in this capture. The saved rows contain output SHA-256 and distinct-byte counts, not output bytes. Consequently this audit checks identifiers, arithmetic, aliases, distributions, and internal consistency; it cannot independently recompute the reported output hashes or distinct-byte counts.

## Exact accounting

The planned Cartesian product was `188 * 21 * 2 * 2 = 15,792` labels. IDEA and Salsa20 were unavailable. The source records one skip before the key loop, so the summary has 376 skip events for each primitive, while each represents 752 omitted labels across two keys. The evaluated grid is exactly `188 * 19 * 2 * 2 = 14,288` unique row identifiers.

There are 7,054 unique output hashes and 7,234 alias rows. Every alias pointer names the first preceding row with the same saved hash. Each of the 19 effective primitives contributes 752 rows. Saved lengths are 546: 7,296; 552: 3,040; 560: 2,736; 576: 608; 102: 304; 96: 152; 104: 76; 98: 76. Every saved output length equals its input length.

The reported minimum distinct-byte count is 71, attained by two short rows. For rows of length at least 546, the minimum is 211. Counts at or below 64 and 70 are both zero; 608 rows are at or below 100.

## Endpoint limits

A `D <= 64` screen applies only after fixing an endpoint whose byte alphabet contains at most 64 values. It does not cover arbitrary classical mappings or variable-length decoders. It also does not cover standard Base64 plus padding and arbitrary accepted whitespace as a 64-byte alphabet: 64 data symbols, `=`, and six ASCII whitespace bytes permit 71 distinct bytes. The included deterministic counterexample has length 98 and `D=71`, and its canonical padded Base64 core decodes after the declared whitespace removal. Thus this census's minimum 71 does not exclude that explicit formatted-Base64 convention.

Reproduce the structural audit with:

```sh
python3 -B research/rev7-20260909-codex/coverage/layer2_census_audit/audit.py
```

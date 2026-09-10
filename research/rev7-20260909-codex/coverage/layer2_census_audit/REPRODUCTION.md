# Restoring the captured census

Identity: ASTRA. This is a structural/source audit, not a cipher rerun. FABLE output bytes and the named stage-A manifest were not present when this audit was frozen. Source-reported distinct-byte values are not independently recomputed.

The captured 14,288-row ledger is published as exact gzip. Restore it only if the JSON is absent, then replay the audit:

```sh
gzip -dk research/rev7-20260909-codex/coverage/layer2_census_audit/upstream/l2census_rows.json.gz
python3 -B research/rev7-20260909-codex/coverage/layer2_census_audit/audit.py
python3 -B research/rev7-20260909-codex/coverage/layer2_census_audit/base64_bound_counterexample.py
```

Raw ledger SHA-256: `043a19052984429cea07bf7247fd5683e2dca9b917b1f1d4448c0d4c66673929`. Gzip SHA-256: `4e717a651eb3213c9970ff307066e8486a588f33497c3213c3b1cf7bd93da495`.

The two D=71 outputs fail direct membership in the fixed Base64-plus-padding-plus-six-whitespace alphabet, according to the captured follow-up source and counts. This does not exclude an unknown bijective byte substitution before that encoding. See LOWD_SUPPLEMENT.md. A corrected-rendering model and a permissive parser that discards arbitrary binary bytes have different coverage; this audit does not infer the author's workflow.

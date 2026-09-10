# Geometry publication note

<!-- identity: ASTRA -->

Compact evidence is available in [geometry_summary.json](geometry_summary.json). It preserves source/canonical hashes, all orientation and block-size metadata, histograms, every minimizer, anchor containment, and greedy symbol-addition data. Only the repetitive per-window endpoint records are omitted from the summary; the complete deterministic ledger is generated locally as `geometry.json` and is not included in this compact publication.

Regenerate and verify the full ledger with:

```sh
python3 research/rev7-20260909-codex/iv_independent/geometry.py
```

The summary records the pinned full-ledger SHA and explicit `target_evaluated: true`, `crypto_evaluated: false` scope.

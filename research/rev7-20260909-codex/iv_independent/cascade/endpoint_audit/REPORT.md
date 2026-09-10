# ASTRA endpoint FSA versus regex completion oracle

Synthetic-only audit (`target_evaluated: false`, `rev7_read: false`) of the current endpoint implementation in `../target/run_target.py`. The independent oracle is a Python `re.fullmatch` compiled once. Its language is TAB/LF/CR, ASCII 32--126, and exactly `E2 80` followed by one of `93 94 98 99 A6`.

All products of 17 representative byte categories through lengths 1--4 were tested: 354,960 nonempty cases across real/real, internal/internal, internal/real-right, and real-left/internal-right boundaries. Internal coordinates satisfy `right-left == len(data)`; internal left completion candidates are `b''`, `E2`, `E280`, and internal right completion candidates are `b''`, `80 93`, `93`. Real boundaries permit only the empty completion.

Result: zero FSA/regex mismatches or counterexamples. Empty intervals were separately checked with valid coordinates and remain `inconclusive_empty`; regex acceptance of empty is deliberately not endpoint acceptance. This validates boolean agreement on the finite synthetic suite only; it makes no target claim.

Reproduce with a new output (existing outputs are refused):

```sh
python3 research/rev7-20260909-codex/iv_independent/cascade/endpoint_audit/endpoint_audit.py --output /tmp/endpoint_audit.json
python3 research/rev7-20260909-codex/iv_independent/cascade/endpoint_audit/endpoint_audit.py --verify /tmp/endpoint_audit.json
```

Hashes: script `b490efe380c87541ffc62d9d8bbba4bda275245cab69c311458ea904c2bdd6e6`, ledger `4727046f73b5de38c49f14619603269b20d30261d2534fb653278531312151c4`, current endpoint source `dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41`.

Identity: ASTRA.

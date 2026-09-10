# Frozen corpus key-scope audit

Identity: **ASTRA**. This is a target-free source and metadata audit. It does not extract, transform, decrypt, or score Rev7 ciphertext.

## Result

Across the six frozen map JSON files, the structured `solution.steps` fields contain 13 modern `decrypt` steps: 12 spell the key `Zombies` and one (`rev2` DES) spells it `ZOMBIES`. Outside `revelations.json`, exactly seven classical steps have a direct structured `key` field, and all seven records have a single recorded step. Inside layered Revelations records, exactly two classical steps have a direct structured key, both `ZOMBIES` (`rev1` Beaufort and `rev11` Playfair).

Those counts describe populated fields, not a closed author vocabulary. Several other keys occur only inside free-text `configuration` fields. Solved `soe6` has no recorded steps. The `rev3` substitution and `de6` homophonic substitution have no structured key or alphabet mapping; `rev6` supplies a substitution alphabet but no separate key. Rev11's final Trifid step also has no explicit key field. Consequently these records cannot prove that an unstructured substitution key, a new key, or a differently layered classical step is absent from Rev7.

Rev3 is a concrete omission example. Its JSON stores the simplified three-step `base10` / checkerboard / substitution account with no explicit key. The pinned MDX separately documents the original four-step solution and gives checkerboard string `fkmcpdyehbigqrosazlutjnwvx` with spare positions 3 and 7. The audit treats this as a documented decode key/alphabet, not proof of the puzzle author's original keyword.

The 52-symbol mixed-case Beaufort implementation itself supplies a direct counterexample to the stronger structural claim. With alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` and key `F`, source-defined Beaufort maps `ABCDEF0123456789` to `FEDCBA0123456789`: letters A-F stay uppercase hexadecimal and digits pass through unchanged. This establishes only that preservation is possible; it is not evidence that Rev7 uses this transform or key.

## Scope and provenance

The nine inventoried data files are the six map files plus `conformance_suite.json`, `evidence_base.json`, and `zombies_sources.csv`. Structured step statistics use only the six map files. The ledger pins all nine, `ra-cli/src/corpus.rs`, and `ra-core/src/nodes.rs`. The loader in `corpus.rs` exposes only three maps as attack targets (`revelations`, `the_giant`, and `gorod_krovi`), another reason not to reinterpret this metadata census as exhaustive search coverage.

Run the read-only replay:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/coverage/corpus_key_scope_audit/audit.py
```

To regenerate to a new path, never overwriting an existing ledger:

```sh
python3 -B research/rev7-20260909-codex/coverage/corpus_key_scope_audit/audit.py --generate /tmp/corpus-key-scope.json
```

The frozen RA data and source dependencies are included in the previously
published `ra_prefix_inventory/upstream_source.tar.gz` archive. Reconstruct
`ra_prefix_inventory/source/ra/` using that package's README before running this
audit in a fresh checkout. No private RA build binary is needed for this audit.

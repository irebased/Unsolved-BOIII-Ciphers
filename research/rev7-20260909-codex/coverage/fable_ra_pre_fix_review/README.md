# ASTRA review of RA raw `--pre` fix

This is a source and focused-control review of RA commit `e127b8d6c17f567b930fe67624d3ea199528b775`, parent `e6c282187cc8a555580349d819210b544e5417b1`. It performs no Rev7 sweep. The two modified sources, complete commit patch, lockfile and exact test receipt are frozen here so the review does not depend on a mutable local checkout.

The core fix is accepted within the reviewed scope. `sweep_input_text` returns `Target.raw` verbatim. Both ordinary execution and claim recomputation use it. `VariantSpace::apply_preserving_whitespace` walks raw bytes, counts only Rust ASCII-whitespace-excluding glyphs, and applies compact-coordinate masks at the corresponding non-whitespace positions. Four exhaustive masks on a spaced two-ambiguity fixture, three `reverse_words` path tests, and the rejected-versus-empty status test passed with Cargo locked and offline.

Three issues affect only the new diagnostic/claim side metadata, not candidate execution:

1. `verify()` never reconstructs or compares `doc["staged_inputs"]`. Structural verification and full Merkle recomputation can therefore pass after those hashes, statuses or collision fields have changed.
2. `xf_staged_inputs` applies each XF to the first pre value directly after display decode. In T3, actual XF runs after layer-1 decryption, so it depends on the selected primitive, key, mode and IV. The saved XF census is a pre-decrypt diagnostic, not T3 intermediate provenance. Later pre values are also absent.
3. `pre_staged_inputs` examines only `variant_masks[0]`, while warning text says the axis contributes no distinct coverage across colliding labels. That conclusion is established only for the named representative reading.

Reproduce the portable source checks:

```sh
python3 -B research/rev7-20260909-codex/coverage/fable_ra_pre_fix_review/audit.py
```

The focused Cargo commands and counts are in `test_receipt.json`. They use a disposable target directory and never invoke a cipher sweep. The two compiler warnings concern a duplicated test attribute and a dead pre-existing post-axis test; they do not alter the reviewed raw-input path.

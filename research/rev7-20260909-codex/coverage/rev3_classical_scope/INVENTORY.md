# Rev3 classical-layer coverage inventory (historical snapshot)

```json
{"identity":"ASTRA","status":"read-only coverage inventory","target_evaluated":false}
```

## Finding

The record does contain a **16-symbol 4×4 Bifid target scan**. It should not be described as only standard 25/26-letter Bifid coverage. FABLE message 217 records 2,546 lore-keyword-derived squares × four Rev7 orientations × 41 periods = 418,036 trials, with zero UTF-8-gate passes and a planted `Maxis` control ranked first. The same message states the exact limit: the scan rests on those 2,546 grounded squares, not all `16!` symbol-to-coordinate bijections; conjugated-matrix two-square Bifid, Nihilist, and Four-square variants were not run. The local session state labels this source/result as not independently verified.

A concrete structural gap therefore remains: **ordinary one-square 4×4 Bifid under an arbitrary permutation of the 16 displayed symbols outside the 2,546 grounded squares**. This is missing recorded coverage, not evidence that the hypothesis is true and not a recommendation to enumerate `16!` blindly. The readable FABLE mirror contains the message-level scope but no corresponding worker source or result ledger, so this inventory cannot upgrade the recorded scan to an independently source-audited finite proof.

## Evidence

- Rev3 is a direct counterexample to the claim that a classical layer requires a letter-valued intermediate. Its documented solve reverses the displayed symbols, converts them through decimal/octal, and then applies a straddling checkerboard; the simpler solve maps the ten symbols to base-10 digits and brute-forces the checkerboard ([`lavender/src/content/docs/ciphers/bo3/rev/rev3.mdx`, lines 24–38](../../../../lavender/src/content/docs/ciphers/bo3/rev/rev3.mdx)). File SHA-256: `0185f674db09dfe542de8ecf2880cf83690cc8331001ebfefa65ddc4f965a243`.
- FABLE message 213 proposes the custom 4×4 family as roughly 636 lore keywords × four letter-to-hex mappings ([`comms/inbox.jsonl`, line 70](../../comms/inbox.jsonl)). Message 217 gives the executed count, control, and explicit `2,546`-rather-than-`16!` limitation ([line 71](../../comms/inbox.jsonl)). Inbox SHA-256: `ac7e568644c638acea0e629cfb259c4eaa5d6a4b0e5caed26ce1e51952dcc603`.
- The frozen session record says: “FABLE217 new Bifid2546squares×4orient×41period418036zero with1plant; source/notindependentverified” ([`SESSION_STATE.md`, line 225](../../SESSION_STATE.md)). SHA-256: `cb9fbe53e6c18a11ca8cd86d4ce6526494acc1fd17b143cf185f5d618ea039b6`.
- The only Bifid implementation found in the readable FABLE filesystem is the legacy CrypTool implementation. It splits/interleaves coordinate digits at lines 18–38, but constructs its square from `$alfa25` at lines 56–67 ([`functions.bifid.php`](/private/tmp/rev7-fable-20260909/cto_legacy/_ctoLegacy/tools/bifid/functions.bifid.php)). SHA-256: `fb4542ac9e3320d83cb41020a8548842e7f8850c24674a1399dc28b210c0234c`. This verifies the historical 25-symbol reference semantics; it does not expose or verify the reported custom 4×4 worker.
- ASTRA’s correction records the scope issue directly: checkerboard decryption consumes digits, arbitrary symbols can label a Polybius alphabet, and base-26/27 conversion produces letters ([`astra_classical_scope_correction.json`, line 1](../../comms/astra_classical_scope_correction.json)). SHA-256: `fa85ce396ab6ff5ce9b3e442833086211b1b18b3a06be678d2a560e7707a6910`.

## Adjacent finite coverage and boundaries

- The coverage matrix records whole-integer base-26/27 and base-5/6 coordinate conversions as conditionally tested, while leaving other layouts and post-conversion fractionation open ([`coverage/REPORT.md`, lines 16–18](../REPORT.md)). It separately states that checkerboard searches used selected boards and leave unknown boards and other layer placement open. These are representation-specific bounds, not closure of arbitrary classical compositions.
- FABLE message 361 reports whole-integer bases 2–36 over four orientations. Base-26/27 outputs are letters by construction, and only readability was assessed; this does not exclude a subsequent checkerboard, substitution, or fractionation layer ([`comms/inbox.jsonl`, line 155](../../comms/inbox.jsonl)).
- ASTRA’s exact base-8/base-10 parser covers 96 direct endpoint cells and explicitly does not exclude later cipher layers ([`whole_numeric/README.md`, lines 11–13 and 28–30](../../whole_numeric/README.md)).
- ASTRA’s base-27 Trifid experiment maps digits through the fixed `ABCDEFGHIJKLMNOPQRSTUVWXYZ.` alphabet and tests only the standard and `ZOMBIES`-keyed coordinate cubes ([`trifid/README.md`, lines 5–10 and 20–23](../../trifid/README.md)). It is useful post-conversion coverage, but it is not an arbitrary checkerboard or arbitrary 4×4 square search.

## Supported conclusion

The available evidence does not decide “modern versus classical.” It supports a narrower statement: a historically motivated 2,546-square 4×4 Bifid family was reported negative, while arbitrary 16-symbol square assignments and unknown checkerboard/layer placements remain outside the demonstrated finite coverage. The absence of the custom worker source in the local mirror means even the 2,546-square result remains a recorded claim rather than an independently reproduced result in this inventory.


## Subsequent verified coverage, 2026-09-10

The inventory above predates the exact even-block Bifid invariant and preserves the scope of the earlier reported searches. It is superseded on even periods by [the proof](../../bifid16_controls/EVEN_PERIOD_INVARIANT.md) and [the target results](../../bifid16_controls/even_target/RESULTS.md): all 2,184 registered even-period/orientation cells are impossible under the 201-codepoint endpoint, for every square. Seven cells remain unresolved under the broader 213-byte Unicode union. Odd periods below the 1,092-symbol message length remain outside this proof. This is a necessary-condition exclusion for a declared construction, not a conclusion about all classical encryption.

The [original Rev3 recipe now has an exact full replay](ORIGINAL_REPLAY.md). The documented classical-only sibling chains are Rev3, Rev4, Rev11, Rev13, and Rev14; listing them does not claim independent verification of every chain. Rev4's displayed input is digits 1–5. Neither a ten-symbol glyph stream nor a digit-valued stream excludes classical layers.

Modern versus classical remains unresolved. Specific finite search failures constrain only their registered encodings, layer order, keys, parameters, and text assumptions. Unknown checkerboards, odd-period square assignments, and further layer compositions remain possible.

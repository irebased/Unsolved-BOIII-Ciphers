# RA partial-block inventory audit

Identity: **ASTRA**. This is post hoc accounting over the frozen RA first-layer result. It performs no decryption, cipher sweep, or rescoring.

RA's pinned mode implementation decrypts each complete ECB/CBC block and retains a trailing partial block unchanged. The captured C/WASM wrapper instead returns `-1` when ECB or CBC decryption input is not block aligned. Every retained RA output has length 546, which is nonaligned for every 8-, 16-, and 32-byte block primitive in this grid.

Applying that strict compatibility filter removes **3,312** READY labels: 1,656 ECB and 1,656 CBC, evenly split as 1,104 labels for each raw pre-operation. They represent **1,890** distinct output hashes, have minimum distinct-byte count **210**, and contain zero occupancy flags. The remaining **8,388** READY labels represent **5,139** distinct output hashes, have minimum distinct-byte count **211**, and also contain zero flags. RC4 and Salsa20 rows are retained even where their labels contain `ecb` or `cbc`, because they are stream primitives and RA ignores the mode label for them.

The C wrapper mode integers are:

- 0: CFB8, corresponding to libmcrypt `cfb` and RA `cfb`.
- 3: full-block CFB, corresponding to libmcrypt `ncfb` and RA `ncfb`.
- 4: full-block OFB, corresponding to libmcrypt `nofb` and RA `nofb`.
- 5: the wrapper's custom counter mode; RA has no matching mode in this inventory.

The old wrapper UI calls code 4 `ofb`, but its implementation encrypts and consumes a whole keystream block at a time. It is full-block OFB/noFB, not byte-feedback OFB8. RA uses the short name `ofb` for its separate OFB8 implementation and `nofb` for full-block OFB.

This comparison narrows which saved RA rows would also execute under that wrapper. It is not an independent C-wrapper replay and does not establish general cipher conformance.

Run the read-only verifier:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/coverage/ra_partial_block_inventory_audit/audit.py
```

Generate a new ledger without overwriting an existing file:

```sh
python3 -B research/rev7-20260909-codex/coverage/ra_partial_block_inventory_audit/audit.py --generate /tmp/ra-partial-block-evidence.json
```

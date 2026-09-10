# Independent replay

Identity: ASTRA. The separate verifier and root's read-only replay both passed every one of the 5,040 saved orders. The verifier does not import the production model. It restores each stream with an inverse-rank index formula and scans maximal equal-symbol runs along gaps 114, 228, ..., 1026. This differs from the production four-symbol seed index. It verifies all witnesses, stream hashes, ordered permutation IDs, scores, the full score distribution and the ZOMBIES ranking, together with pinned source and canonical-input hashes.

ZOMBIES has 195 strictly higher orders and 535 tied orders, including itself. The 730 orders at or above its score are 14.4841269841% of this fixed 5,040-order census. This is a descriptive proportion within the registered axis, not a global p-value or a correction for the outside program's unknown earlier search. The repeat signal does not isolate ZOMBIES.

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44_keyorder_census/verify_results.py
```

The default command is read-only. It checks the saved result; it never invokes the production target driver or replaces the evidence. The original census completed once. README.md preserves the preparation protocol; RESULTS.md describes that original run.

- Target result SHA256: `6edb51727cef5eac35d225827877bf9df7c2f3724109459b8024c36eba8bf36a`
- Verifier source SHA256: `4bc99a1325cf5a8fd68d2b1cd3969a59a548acb8dfba2d1b6be9e6c543af0542`
- Verifier synthetic controls SHA256: `1eaf28775811b25a071939d9792df55ec42644682afad94c0e204326258c3c5b`
- Verification ledger SHA256: `b449d65b96453d2403bc5f8b6d3591a247039112ba6b18a7854d4c4a701fe492`

The model and every target record concern conventional equal-cut-4 column decoding of the canonical forward input. The outside Z formula and aggregation rules remain unconfirmed. No cipher family, plaintext or key length has been established by this comparison.

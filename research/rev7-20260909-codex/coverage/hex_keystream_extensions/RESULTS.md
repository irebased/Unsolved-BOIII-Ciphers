# Hex substitution and fixed-keystream extension result

Identity: ASTRA. Rev7 is still unsolved.

All 2,700 frozen contexts were evaluated once and independently verified. Every upper bound on allowed ASCII bytes is below 410 of 546. Bounds range from 273 to 331; ten contexts used the exact maximum-weight assignment bound, zero used the pair bound, and no result depends on a CSP unsatisfiability claim. All 2,700 also exclude complete ASCII under the declared model.

The new grid has 1,560 additional-key full-OFB/CTR/stream labels and 1,140 historical-OFB8 labels. Of these, 2,660 have captured block/recurrence source support and 40 Panama/Arcfour labels are conditional on empirically tested fixed-XOR behavior. Forty exact keystream/orientation labels overlap older strict-stream records. The previous 780-context run was not repeated. All 16! global hex-symbol bijections are covered by necessary-condition bounds; unknown keys, other feedback modes, position-dependent maps, and arbitrary inner binary layers are outside this result.

## Evidence

- Target execution: root session 24877, final chunk 800235, exit 0; one run.
- Full result SHA-256: `4f183b3f688a830fe880bccf078c1ac79dc5090a976ebd26768e18347bdfd243` (19,018,549 bytes).
- Exact gzip SHA-256: `3c6eae63635793bc34be227870aee21568ea2619fe7e7ed0be91fb0e728717e7` (2,703,285 bytes).
- Independent verification receipt: `e2e2cbff68db73fb0304db86785d24b5dcf6d6f33c03b4213679546f8faae70e`.
- Frozen verifier source: `51462df2cd40c065ddda378ae0f25d49e1d9dd06f36f776e37cf3a7351b186c7`.
- Authorized gate: `8bc4e3cacf0b7c7131b79cc2fc9c3f5c4ec832d492cb8b5f0321750f45287d68`.

The verifier rebuilt all matrices and exact assignment optima from saved keystreams without rerunning cryptography. Family A has full 546-byte control hashes; family B binds 64-byte controls, with 256-byte independent AES/DES/Blowfish references and cross-orientation full-stream equality. These evidence lengths are not interchangeable. See ROOT_REVIEW.md, FINAL_REVIEW.md, and the controls ledger.

A const-reassignment runtime bug in the independent verifier was fixed before target execution. The repaired assignment routine was actually executed on zero, diagonal, and eight exhaustive reduced fixtures, rather than relying on syntax checking. Frozen target sources were unchanged.

## Reproduction

After cloning the published branch, restore the large saved artifact (only if absent), then verify:

```sh
gzip -dk research/rev7-20260909-codex/coverage/hex_keystream_extensions/target_results.json.gz
node research/rev7-20260909-codex/coverage/hex_keystream_extensions/verify_result.js
```

The driver refuses an existing target result. Source, controls, inert and authorized gates are included for reproducibility; ordinary review needs only the saved-result verifier. The target run was preregistered in FABLE bus message 804.

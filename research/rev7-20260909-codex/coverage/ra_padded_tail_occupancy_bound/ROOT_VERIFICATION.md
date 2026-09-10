# Independent root verification

Identity: ASTRA. Root reviewed the lemma and frozen evaluator, then ran
`verify_saved.py` once after the original saved-result evaluation completed.
The verifier uses a manual last-nonzero scan instead of rstrip, a bitmask
distinct count, and separately checks EVERY integer candidate output length
against the published table. It checks all3,312 row descriptors, source bytes,
prefix/Q hashes, bounds and summary counts without importing the production
model. Actual process f5baef exited0. No new decryption was performed.

```sh
python3 -B research/rev7-20260909-codex/coverage/ra_padded_tail_occupancy_bound/verify_saved.py
```

The original saved result is unchanged. `verification.json` retains the
independent source hash and exact checks. The result remains conditional on
the first544 plaintext bytes being invariant; it does not establish historical
key derivation, IV handling, or a site-specific output policy.

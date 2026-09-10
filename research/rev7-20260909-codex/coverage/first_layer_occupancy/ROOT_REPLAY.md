# Root verification

Identity: ASTRA. The original target pass completed once and remains unchanged.
Root's separate read-only verifier passed19 synthetic orientation/threshold checks,
then replayed all1,560 cipher calls and verified every saved output SHA256 and
all3,080 independent histogram scores. This deliberately reuses the pinned
cipher runtime, so it verifies reconstruction, accounting and scoring rather
than an independent cipher implementation. Both runs found zero flags.

```sh
node research/rev7-20260909-codex/coverage/first_layer_occupancy/verify_replay.js --controls-only
node research/rev7-20260909-codex/coverage/first_layer_occupancy/verify_replay.js
```

The verification source, source hash and results are retained in
`verify_replay.js` and `verification.json`. Root actual replay exited0
(command chunk0f8bb7). No further target execution remains active.

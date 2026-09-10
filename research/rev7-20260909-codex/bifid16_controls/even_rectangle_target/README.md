# Seven even-period rectangle certificates

Identity: ASTRA. The registered seven-cell run is complete: all seven are excluded under bag213. See [RESULTS.md](RESULTS.md) for the proof, exact scope, seven-row table and final 4,368-cell one-square reconciliation.

The driver recomputes every orientation and pair stream directly and matches each prior even-period record before testing all 1,820 four-symbol row sets. The independent `--verify` path reconstructs all missing-column masks through direct edge membership. No solver is called.

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/driver_controls.py
python3 -B research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/run_target.py --verify
python3 -B research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/reconcile_broad.py
```

These commands require the earlier even ledger. In a clean checkout, restore it with `even_target/pack_results.py --restore` and the explicit output path described in `../complete_transport/REPRODUCE.md`. The standard-library rectangle verification itself does not need Z3 or the large formula archive. The frozen gate pins all inputs, source and controls. The target command refuses an existing result; use verification commands for the published evidence.

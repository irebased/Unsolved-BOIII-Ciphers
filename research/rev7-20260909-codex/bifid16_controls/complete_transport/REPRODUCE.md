# Restore the complete Bifid formula evidence

Identity: ASTRA. Run these commands from the repository root. All 2,175 original gzip records were packed once, verified, restored into a new directory, and directly compared byte for byte against the originals. The saved receipts record these checks.

The 17 parts total 52,686,820 bytes and restore 135,693,674 bytes. `full_bundle/manifest.json` binds the complete ordered record union, every part and record hash, the completed target/checkpoint, the accepted source gate and the successful formula-verification receipt. Its SHA-256 is `69858bbc8f1cef2161bcd5f760a364bc7f6312664fb6242a18116f66d594e01e`.

Verify the portable archive without Z3:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_transport/bundle.py --verify research/rev7-20260909-codex/bifid16_controls/complete_transport/full_bundle
```

Restore into the corresponding package directory in a fresh checkout:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_transport/bundle.py --restore research/rev7-20260909-codex/bifid16_controls/complete_transport/full_bundle research/rev7-20260909-codex/bifid16_controls
```

The helper checks every part before restoration. Existing identical files are verified; differing files and symlink destinations are refused. To inspect a separate restored copy, replace only the final destination argument with a new directory. The restored relative paths begin `complete_periods/smt/`.

Before full formula reconstruction, install the exact runtime using `../SMT_REPRODUCE.md` and restore the older evidence:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/restore_smt.py --restore
python3 -B research/rev7-20260909-codex/bifid16_controls/even_target/pack_results.py --restore research/rev7-20260909-codex/bifid16_controls/even_target/target_results.json
python3 -B research/rev7-20260909-codex/bifid16_controls/complete_periods/verify_results.py
```

The even-ledger restore requires an absent output path. If it is already present, invoke `pack_results.py` without arguments to verify it instead. The full formula check can take sustained CPU time; it rebuilds the exact input formulas and does not repeat the search.

The completed solver's seven UNKNOWN rows are preserved. Their later standard-library rectangle proof and its independent direct-edge verifier are in `../even_rectangle_target/`. No result status was rewritten to hide a timeout.

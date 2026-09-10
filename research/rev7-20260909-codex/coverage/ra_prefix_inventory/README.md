# RA first-layer prefix inventory

Identity **ASTRA**. This private source snapshot is based on RA commit
`e127b8d6c17f567b930fe67624d3ea199528b775`. `snapshot.patch` is the complete
CLI extension relative to that commit. It adds `ra prefix-inventory` inside the
existing `sweep` module so it calls the actual `Ctx::stage` raw-`Pre` path and
`LayerParams::decrypt`, stopping at the returned bytes before XF, codec, layer
2, post, or any RA oracle.

The registered grid is exactly `hex-exact` × `{identity,reverse,reverse_words}` × the
saved baseline layer domain: 16 primitives, 7 modes, 6 literal key labels, 4
key derivations, and 2 IVs. This is 16,128 labelled contexts. Tool formatting
is exactly `none`. Each successful output retains its exact bytes, length,
SHA-256, 256-bin histogram and distinct-byte count. Exact byte equality forms
alias groups while all parameter labels remain present. Empty successful
outputs and inapplicable layers have different statuses. There is no hit cap.

`score_inventory.js` applies the already published `score.js` and frozen
threshold table to each complete output only. Lengths outside 128..1092 receive
the scorer's null/untested status. Occupancy flags retain outputs for review;
they are not cipher exclusions.

The synthetic control uses an actual AES/CFB8 RA encryption and decryption of a
200-byte plaintext over 40 byte labels. Separate raw displays exercise
`identity`, `reverse` and `reverse_words`; each exact truth appears once in the intended
labelled context. An odd hexadecimal input normalizes to an empty canonical
buffer under RA's actual decoder and verifies that successful-empty and
layer-inapplicable statuses remain distinct. The published JS scorer reports
D=40 and `flagged` on the full plant, while n=127 and n=1093 remain untested.

Build used:

```
cargo build --manifest-path research/rev7-20260909-codex/coverage/ra_prefix_inventory/source/ra/Cargo.toml --locked --release --target-dir research/rev7-20260909-codex/coverage/ra_prefix_inventory/build/target -p ra-cli
```

Read-only checks, which do not load Rev7:

```
node research/rev7-20260909-codex/coverage/ra_prefix_inventory/controls.js
python3 -B research/rev7-20260909-codex/coverage/ra_prefix_inventory/run_target.py
```

Target execution additionally requires `--run-target`, an authorized frozen
`target_gate.json`, and absent result/temp paths. The gate is intentionally not
created before external preregistration and root review.

Root repeated the actual synthetic engine control successfully with:

```sh
research/rev7-20260909-codex/coverage/ra_prefix_inventory/build/target/release/ra --data research/rev7-20260909-codex/coverage/ra_prefix_inventory/source/ra/data prefix-inventory --output NEW_CONTROL_FILE.json
```

The CLI requires an explicit data directory in this private layout even for
synthetic controls; these controls do not call the target loader. The first
root invocation omitted `--data` and exited before any control ran. The corrected
invocation exactly matched the frozen control ledger. Root also compared all
242 unchanged upstream files with the pinned archive, verified the two changed
files and new module, and checked that Rev7's raw text matches the canonical
dataset including whitespace. See `ROOT_REVIEW.json`.

`upstream_source.tar.gz` is a fixed-mtime gzip of the exact original `git archive`
at the pinned commit. Extract it into `source/ra/` and apply `snapshot.patch`
there to reconstruct the private source before building. Cargo dependencies are
identified by the archived `Cargo.lock`. Build binaries are not published.

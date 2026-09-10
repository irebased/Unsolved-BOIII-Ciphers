# Packed periodic byte-bag result

Identity: ASTRA.

The frozen 8,583,401-byte target_results.json is transported losslessly as deterministic gzip with compression level 9, modification time zero, and Base64 inside target_results.pack.json.

Hashes:

- raw SHA-256: 008966a182ee38ff9ffac569e715d91bab8c05cf37ae5c2c6043dc0d6b1c9acc
- compressed gzip SHA-256: c8712e3499e03188d3acb7063a682a5628833bf4c9c4a2abff028498c30fd6e9
- packed JSON SHA-256: 36e439807210c9ae9b8973022b1b65320e57d96fd3433ef3b89c7829c8b28adc

Default verification decompresses in memory, checks the complete gzip stream and all lengths and hashes, parses the result identity and 512-cell count, and compares the raw file when it is present:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/target/pack_results.py

Restore to an absent path without overwriting:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/target/pack_results.py --restore /tmp/periodic_target_results.json

Rebuild the deterministic envelope from the pinned raw file to an absent path:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/target/pack_results.py --build /tmp/periodic_target_results.pack.json

Packing does not rerun or alter the target experiment.

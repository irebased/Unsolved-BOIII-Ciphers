# Independent RA prefix-inventory verifier

Identity: ASTRA. This package performs no decryption and does not read canonical Rev7 bytes. It validates the saved RA first-layer inventory produced by the separate `ra_prefix_inventory` package.

The verifier independently constructs the ordered Cartesian grid:

- three pretransforms: identity, reverse, reverse_words;
- 16 primitives;
- seven modes;
- six literal key labels;
- four key derivations;
- two IVs.

IV is the fastest-varying axis and pretransform is the outer axis. The expected count is 16,128 unique IDs. For every successful row it decodes the retained buffer, checks exact length and SHA-256, rebuilds all 256 histogram bins and the distinct-byte count, and independently applies the published threshold table. Only complete returned buffers are scored. Empty successful rows remain distinct from inapplicable and decode-failed rows.

Exact-output aliases are reconstructed from byte equality, including empty output. The saved group order, membership, lengths and hashes must match those independently rebuilt classes. The report summarizes status and length counts, unique byte outputs, every occupancy flag, the minimum D with lengths, and the smallest threshold margin with lengths.

JSON and deterministic gzip JSON are accepted. A gzip container must have mtime zero. Default operation runs synthetic controls first. The positive fixture contains duplicate and distinct 128-byte outputs plus an empty output. Five corrupted copies independently demonstrate rejection of byte/hash inconsistency, a bad histogram, altered alias membership, a duplicate ID and an altered occupancy score.

Commands:

    python3 -B research/rev7-20260909-codex/coverage/ra_prefix_inventory_verification/verify_inventory.py

After a result exists, the default discovers target_results.json or target_results.json.gz. A path may also be supplied explicitly:

    python3 -B research/rev7-20260909-codex/coverage/ra_prefix_inventory_verification/verify_inventory.py /path/to/target_results.json.gz

This is saved-result integrity and accounting verification. It does not independently repeat any cipher operation or establish cryptographic correctness.

# Byte-column research overview

Identity: ASTRA.

The files in this directory represent two frozen stages:

- `README.md` and `controls.json` describe the synthetic-only control snapshot made before target authorization. Its statement that no target driver existed is historical status for that snapshot.
- `TARGET.md`, `target_gate.json`, `target_results.json`, and `RESULTS.md` record the later preregistered target scope and completed finite result.

The target result is 16 of 16 cells exhaustive, zero capped, zero survivors. Its SHA-256 is `90902426dbe074a13098e54f136e3ee43677d6da3fb9b6f0ee525b7958c6d8a9`. The finite limits and per-cell counters are in `RESULTS.md`.

## Read-only verification

From `/private/tmp/rev7-astra-20260909`, verify the stored artifact hashes, exact 16-cell Cartesian scope, per-cell factorial certificates, summary, and result hash without decrypting the target again:

```sh
python3 -B research/byte_columnar/verify_results.py
```

`verify_results.py --replay-scratch` is an optional full replay. It compiles `native.cpp` into an operating-system temporary directory, reruns the 16 registered cells, and compares mathematical counters and survivor payloads while excluding `elapsed_seconds`. This optional replay was not run while preparing this overview because the frozen target already completed and no new target run was authorized.

The scratch build command assumes the recorded macOS Homebrew OpenSSL paths:

- headers: `/opt/homebrew/opt/openssl@3/include`
- library: `/opt/homebrew/opt/openssl@3/lib`

Those paths and the compiled binary hash are platform-specific. Rebuilding can change the binary hash, timing fields, and a regenerated control JSON even when mathematical counters agree. The frozen gate and results remain the audit record; a local rebuild should compare the counter fields rather than expect identical elapsed times or artifact hashes.

Additional design work for ragged widths and an all-IV variant-B suffix proof is in `RAGGED_ASSESSMENT.md`. It is an assessment only and contains no additional target result.

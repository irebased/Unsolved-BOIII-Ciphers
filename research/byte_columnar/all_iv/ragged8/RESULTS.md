# Ragged variant-B 8-byte-block all-IV target results

Identity: **ASTRA**

The preregistered 708-context evaluation completed once. All **708 cells closed** and **0 remained unresolved**.

The fixed scope was:

- DES, key `Zombies\0`;
- standard Blowfish, raw key `Zombies`;
- historical Blowfish-compat, raw key `Zombies`;
- CFB8 and every external eight-byte IV;
- FABLE variant B with both first-long and last-long ragged conventions;
- widths 2 through 60 and four canonical orientations;
- TAB, LF, CR, printable ASCII, and UTF-8 U+2013, U+2014, U+2018, U+2019, and U+2026.

Each closed cell contains an unavoidable natural ciphertext chunk whose IV-independent suffix rejects from all three possible endpoint boundary states. This excludes all `w!` orders under each ragged convention for every external IV. The per-convention certificates are parallel and are not added. Rectangular cases explicitly mark the conventions as aliases.

Per-cipher results:

| Cipher | Cells | Closed | Unresolved | Prefixes examined | Rejecting-rank distribution |
|---|---:|---:|---:|---:|---|
| DES | 236 | 236 | 0 | 250 | rank 0: 225; rank 1: 9; rank 2: 1; rank 3: 1 |
| Blowfish | 236 | 236 | 0 | 252 | rank 0: 225; rank 1: 7; rank 2: 3; rank 3: 1 |
| Blowfish-compat | 236 | 236 | 0 | 265 | rank 0: 220; rank 1: 10; rank 2: 2; rank 3: 3; rank 6: 1 |
| **Total** | **708** | **708** | **0** | **767** | |

Independent post-run verification reconstructed the exact Cartesian set of 708 cells and replayed all 767 stored prefixes. It checked every prefix slice, recomputed every suffix with an implementation separate from the search core, matched CFB8 suffixes under two external IVs, reran the endpoint automaton, confirmed one final rejecting witness per cell, and checked each per-convention factorial weight. For Blowfish-compat, the replay used the independently established PyCryptodome word-reversal conjugation rather than the pinned C adapter used by the search core.

Artifacts:

- `target_results.json`: 1,379,944 bytes; SHA-256 `a985c8008c285763e5001470957e1d9788bac3df21a95260f274ad6c35ab0a83`
- `target_results_compact.json`: 978,732 bytes; SHA-256 `f7b53f894c0fe9748d7fed6bbd861ebdaa7affde39c5a1ccf30ff1c7db70086e`
- `target_gate.json`: 3,379 bytes; SHA-256 `3abaf463714cd066546effb01a50d6653c2794bb11b9fd9e316218d07ad82fca`
- `controls.json`: 38,358 bytes; SHA-256 `526ebeb27636c559d972f5e4bf29805f8962f8d54e70385da7956d396a644afa`

The compact result is a deterministic, sorted-key, whitespace-minimized serialization of the complete result object. It is semantically identical to the full ledger and retains every examined prefix, suffix, failure, cell field, scope field, and certificate. It was derived after the run; no target work was repeated.

Executed once:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged8/run_target.py --run-target
```

Finite limits: these results exclude only the registered variant-B mappings for the three fixed primitives and endpoint. They do not cover variant A, widths above 60, other keys, ciphers, modes, arbitrary framing, endpoints, or transposition families. The specific whole-frame raw-IV-prefix interpretation follows from the [framing corollary](../../../rev7-20260909-codex/iv_independent/raw_iv_prefix/README.md) without a new run.

The compact ledger is published; the larger pretty serialization can be reconstructed from it without target work. Verify every witness and the reconstructed full-ledger digest using Python and PyCryptodome, with no compiled library required:

```sh
python3 -B research/byte_columnar/all_iv/ragged8/verify_results.py
```

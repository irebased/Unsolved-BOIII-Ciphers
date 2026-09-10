# Contiguous-interval stream robustness result

**Identity:** ASTRA

## Result

The preregistered 96-cell arithmetic grid completed successfully. All frozen source-stream hashes and all ordered context identifiers matched.

For the 92 nonzero-stream contexts, the shortest feasible contiguous ignored span is **163–292 bytes** in the applicable oriented decoded-byte sequence. Every one of those 92 cells has exactly one minimizing interval. The minimum of 163 occurs for standard DES/OFB8 with the SHA-1-prefix IV in the reverse and byte-reverse orientations, at `[298,461)`. The maximum of 292 occurs for standard AES-128/full-block OFB with the SHA-1-prefix IV in the forward and nibble-swap orientations, at `[231,523)`.

The remaining four contexts are standard Blowfish/OFB8 with the NUL IV and its all-zero keystream, one per orientation. Under the registered arbitrary noninjective fixed mapping, each has minimum span 0. All 547 half-open empty intervals `[i,i)` are retained in the ledger, with one representative map per cell. This zero-span statement does not apply to injective mappings.

## Independent certificates

For each pair class, the driver independently builds occurrence positions and prefix/suffix intersections of 256-bit candidate masks. Bisecting the occurrence positions gives the exact candidate set outside any interval.

For every nonzero minimum `L`, the certificate checks every interval of length `L-1` and proves each infeasible, then checks every interval of length `L` and reproduces the solver's complete minimizing-interval list. A feasible shorter interval could be extended within the 546-byte sequence to length `L-1`, so the failed `L-1` boundary excludes every shorter length. A feasible zero-length interval is minimal by definition.

Across the 96 cells, the ledger records:

- 27,832 intervals checked at `L-1`, comprising 6,290,032 pair-mask checks.
- 29,928 intervals checked at `L`, comprising 6,763,728 pair-mask checks.
- Exact retention of every minimizing interval.
- One representative arbitrary map per cell, rechecked at every position outside its selected interval.
- 96 matching keystream SHA-256 values and ordered context identifiers.

A separate post-run audit repeated all representative outside-position checks and verified every certificate-count formula and minimizing interval. The measured per-cell computation totals 4.952 seconds; wall time includes process and serialization overhead.

## Artifacts and reproduction

The complete ledger is `target_results.json`:

- Size: **738,380 bytes**
- SHA-256: `6a891c17eee5274ea48ec78a1fcc158178cf4043621ba8bc17a50afd167cbe00`

Frozen execution inputs:

- `run_target.py`: `42b1429579dd6b8647f956981a6a5a0031eca6999900860d3b0d991f2b54b6bb`
- `target_gate.json`: `285e8f20e641fd3153220611550e188e780348abf224c126f8825330afee5177`
- `interval.py`: `03fd7e3fb18c94e721e6e648f84fa315d8e491b306d53b2dffef6a8245061919`
- `controls.py`: `9489457179cc7cf447f6f798221fd65b525e672ababd3f64e248b83ae5b93628`
- `controls.json`: `98a6fc705f39b68c3322aa9b82b5a227ca12684165c54b136a31f1df6a56d5fd`
- Full robustness ledger: `22e4297ab94da5ebd530e5b7ec0be2299678edf8ac2ea2c1b1b82bfc4e0b2c3a`
- Compact robustness ledger: `7c10d4d79049f640180a9c759e3eae1bd2fc17437654dbbd6ff93088852fe2c6`

Run from a clean checkout without an existing final output:

```text
python3 -B research/rev7-20260909-codex/stream_robustness/interval/run_target.py --run-target
```

The driver writes an atomic checkpoint after each cell and refuses to overwrite an existing final ledger.

## Scope

Each result is a lower bound on the span required for one contiguous corruption region under the registered fixed-length OFB-stream context, 105-byte relaxed alphabet, and arbitrary fixed noninjective displayed-pair-to-byte mapping. Coordinates are half-open intervals in each oriented decoded-byte sequence. A span is not a count of altered bytes.

The optimizer permits noninjective mappings. Its positive span bounds remain necessary for injective byte mappings and global hex-symbol bijections, but it does not establish the exact optimum for those stricter models. It does not cover multiple disjoint corruption regions, insertion or deletion, alternate streams, keys or IVs, or CFB.

Within the 92 nonzero-stream contexts, a contiguous region of 128 displayed hex symbols cannot explain the mismatch: it touches at most 65 decoded-byte positions, while every minimum span exceeds 65. This conclusion assumes the registered fixed byte-pair map and unchanged stream alignment. The separate zero-stream injective correction-count bound of 179 positions also exceeds 65; that uses a different bound, not the zero-span arbitrary-map result.

Read-only certificate replay (uses the regenerated parent robustness ledger; see its report for compiler and library prerequisites):

```sh
python3 -B research/rev7-20260909-codex/stream_robustness/interval/verify_results.py
```

This verifies the stored result and does not rerun the optimizer or reconstruct cryptography. The arithmetic verifier itself uses only the standard library.

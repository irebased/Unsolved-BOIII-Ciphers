# ASTRA018: unknown hex alphabet before CFB8

Identity: ASTRA. This directory records the approved target run for an unknown bijection of all 16 hexadecimal symbols before byte decoding and CFB8 decryption.

## Result

The target driver completed all 12 cells: AES-128, Blowfish, and DES, each over forward, full hex-symbol reversal, reversal of the order of two-symbol byte pairs, and per-byte nibble swap. Every cell reached its per-cell DFS cap of 10,000,000 nodes (`complete: false`), produced zero survivors, and produced zero complete mappings. The run is therefore a bounded negative result; it is not an exhaustive exclusion of the 16! = 20,922,789,888,000 mappings in any cell.

The initial driver output was:

```json
{"identity":"ASTRA","controls":"passed","target_cells":12}
```

The saved `results.json` reports `all_cells_finished: true`, `capped_cells: 12`, `complete_cells: 0`, and `survivor_records: 0`. Across cells it records 120,000,000 DFS nodes and 193,482,893 rejected plaintext prefixes. Mapping weights are interpreted separately per cell.

## Exact scope

- Cipher/key/IV: AES-128 with `b"Zombies" + 9*NUL`; standard Blowfish with the raw seven-byte `b"Zombies"` key; DES with `b"Zombies" + NUL`. IV is ASCII `0` bytes at the cipher block size. These are the exact tested conventions, not a claim of full historical frontend equivalence.
- Input: verified 1,092-symbol Rev7 transcription, SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`.
- Mapping: arbitrary bijection from displayed hex symbols to nibble values, applied before byte decoding.
- Endpoint: TAB/LF/CR, ASCII 32–126, and UTF-8 en dash/em dash/curly quote forms, with complete termination.
- Worker/cap: one sequential worker; 10,000,000 DFS entries per cell, including terminal entries.

The factorial certificate concept is exact only when a cell completes: rejected completion weight plus terminal completion weight must equal 16!. Because all 12 target cells were capped, their remaining `unaccounted_mapping_weight` is nonzero and no factorial certificate proves total coverage.

## Controls and audits

The driver reran its controls before the target and recorded `controls: passed`. The independent `audit_core.py` audit executes synthetic data only (`target_evaluated: false`): 36 synthetic fixtures, including complete-byte and UTF-8 boundary cases, passed the DFS-vs-naive comparison. It tested 2,592 naive full mappings and includes a node-cap control. These controls validate the recognizer, mapping/byte conversions, CFB8 oracle and audit accounting; they do not authenticate target plaintext.

Run from the repository root with Python 3.9+:

```sh
python3 -B research/rev7-20260909-codex/hex_cfb/run_target.py --target
python3 research/rev7-20260909-codex/hex_cfb/audit_core.py
```

Both the target (through `prototype.py`) and audit require PyCryptodome 3.23.0 (`Crypto.Cipher`), pinned in the parent `requirements.txt`. The target results are checkpointed after each cell. The driver refuses to rerun when `results.json` already exists. Resume requires an explicit continuation implementation; increasing the cap or completing the factorial certificate would be a new run and must preserve this capped result.

## Hashes

- `results.json`: `8c5567bd7cd3d66e926fddd1a5df39b684c29d7387e63418e26104d0fcaab939`
- `audit_core_results.json`: `0ca634fc07a092c3225e9c20ab8cf506ea4e3f8e2597df96b9726c8ca7e294e2`
- `run_target.py`: `8441194f0c8701b4e5c81b9954d0a09168e65e4e9ec625c2ed0467a7c16d4bd4`
- `prototype.py`: `416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b`
- `audit_core.py`: `193e9eda4b9cb59cb6a68e2422436217d162268f682956e58d5646edc26eac92` (recorded as `audit_source_sha256`)

The prototype source hash reflects the documentation-only wording correction; the computation is unchanged.

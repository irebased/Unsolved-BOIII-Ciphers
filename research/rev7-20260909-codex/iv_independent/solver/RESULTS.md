# DES CFB8 all-IV suffix search result

Identity: `ASTRA`

## Result

The four preregistered cells completed without reaching the 1,000,000,000 accepted-DFS-entry cap. No mapping survived in any orientation.

| Orientation | Accepted DFS entries | DES ECB calls | Certificate weight | Unaccounted | Survivors | Seconds |
|---|---:|---:|---:|---:|---:|---:|
| forward | 295,886,952 | 2,707,359,465 | 20,922,789,888,000 | 0 | 0 | 188.039 |
| reverse | 295,777,434 | 2,706,362,040 | 20,922,789,888,000 | 0 | 0 | 186.088 |
| byte_reverse | 295,632,228 | 2,704,969,801 | 20,922,789,888,000 | 0 | 0 | 185.511 |
| nibble_swap | 295,848,086 | 2,707,009,598 | 20,922,789,888,000 | 0 | 0 | 188.092 |
| **Total** | **1,183,144,700** | **10,825,700,904** | — | **0** | **0** | **747.730** |

Each cell has `certificate_complete=true`, `aborted_at_node_limit=false`, and certificate weight `16! = 20,922,789,888,000`. Native geometry matched the frozen Python geometry exactly in all four cells. Because there were no survivors, the conditional survivor-validation path had no candidates to process.

## Frozen model

The search uses DES with key bytes `5a6f6d6269657300` (`Zombies` plus NUL) in CFB8. It tests a global bijection from the 16 displayed hexadecimal symbols to nibble values in the four canonical orientations. For byte position `i >= 8`, it applies the IV-independent recurrence

`P_i = C_i XOR DES_key(C[i-8:i])[0]`.

The necessary byte filter permits TAB, LF, CR, ASCII 32–126, and bytes `80 93 94 98 99 A6 E2`. Complete suffixes must satisfy the strict UTF-8 endpoint with `E2 80 93/94/98/99/A6`, an initial state in `{0,1,2}`, and terminal state 0. The external eight-byte IV is arbitrary and was neither recovered nor searched. Accordingly, this is an exhaustive exclusion for the 538-byte suffix under the stated model; it does not recover or characterize the first eight plaintext bytes.

## Reproduction

Run from the repository root:

```sh
python3 -B research/rev7-20260909-codex/iv_independent/solver/run_target.py --run-target
```

The driver refuses an existing final ledger and uses an atomic per-cell checkpoint. The completed ledger is `target_results.json`, SHA-256 `3e6edd3da51ba30fb1cd8646282a4110cf8b223d1f36c7400ccbd2c7c1a4fc1e`.

Frozen target files:

- `run_target.py`: `988b3fc575a1421c447891ec90b41712c6887f56f2b1a7ef2d2ef3b5992634ad`
- `target_gate.json`: `b0f0cffd6c148628d020e0eae614c5419af0dd28453ed82d99c1d6f3b00050bf`
- native binary: `f205a6493ead64be879b24e308c28839aab2bc3db383bb9e743cab24f8de1574`
- `native.cpp`: `77b169a90041f57eb506134fdcdfdde0c255377c9fad60117e158132078ea1cc`
- `solver.py`: `23b8755b61276f9a3fc30b1ab385dd7296cffd95407eed9663f505553f949343`
- `native_controls.json`: `9eb64df3639e671f2371ccd274306ee0c0af0bfed5bc1c416c6ecd996c5d211d`
- `controls.json`: `8656075b2f0495444b82439d582f075e28030189d9985489301b9c030159926b`
- canonical target text: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

The same certificate also excludes interpreting the same 546 mapped bytes as an eight-byte raw IV followed by 538 CFB8 ciphertext bytes, with the mapping acting on the entire frame. The recurrence then gives the actual payload at every tested suffix position. This [raw-IV-prefix corollary](../raw_iv_prefix/README.md) changes no geometry and requires no new target run; arbitrary framing is outside this deduction.

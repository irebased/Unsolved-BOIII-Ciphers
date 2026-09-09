# Native Base64/CFB8 target results

Identity: ASTRA. Completed 2026-09-10 with the preregistered command:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/hex_cfb/native/run_target.py --run-target
```

All 12 native 3,000,000-node prefix replays exactly matched the frozen Python
ledger's raw DFS counters, factorial weights, mappings, and plaintext survivors.
That phase reproduced six already-complete cells and six capped cells, with no
survivors. Its summed native search time was 1.981210 seconds.

Each of the six preregistered fresh-root extensions completed before the
100,000,000-node cap:

| Cipher | Orientation | DFS entries | Native seconds | Certificate | Survivors |
| --- | --- | ---: | ---: | ---: | ---: |
| AES128 | forward | 13,878,204 | 0.820197 | 20,922,789,888,000 | 0 |
| AES128 | nibble swap | 13,650,074 | 0.807188 | 20,922,789,888,000 | 0 |
| Blowfish | forward | 13,561,821 | 0.837100 | 20,922,789,888,000 | 0 |
| Blowfish | nibble swap | 13,079,776 | 0.823779 | 20,922,789,888,000 | 0 |
| DES | forward | 13,702,440 | 1.155080 | 20,922,789,888,000 | 0 |
| DES | nibble swap | 13,528,758 | 1.148590 | 20,922,789,888,000 | 0 |

The extension phase visited 81,401,073 DFS entries in 5.591934 native seconds.
For every cell, rejected plus terminal completion weight equals
`16! = 20,922,789,888,000`. Combining these six certificates with the six
complete reverse and byte-reverse cells from the exactly reproduced prefix
ledger gives exhaustive coverage of all 12 registered cells.

Within the registered model, there is no plaintext consisting solely of the
69 allowed Base64 endpoint bytes under any global permutation of the 16
displayed hex symbols, for AES128, raw-seven-byte Blowfish, or DES with the
registered ASCII-zero IV, in forward, reverse, byte-reverse, or nibble-swap
orientation.

Result artifact:

- `target_results.json` SHA-256:
  `74ce86bd01c4bbeb1492f61707039d07884ac7c3d9b63ec20bde5ea3d9301644`

The scope is finite and specific. It does not cover other keys, IVs, feedback
modes, encodings, byte predicates, or transformations.

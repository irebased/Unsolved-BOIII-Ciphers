# Blowfish compatibility CFB8 results

Identity: ASTRA.

All four registered orientations completed below the fresh-root one-billion-node cap, with zero endpoint survivors. Each rejected mapping certificate is exactly 16! = 20,922,789,888,000; terminal weight and uncovered weight are zero.

| Orientation | DFS nodes | Native seconds |
|---|---:|---:|
| forward | 340,975,196 | 29.67140 |
| reverse | 34,632,838 | 3.13877 |
| byte_reverse | 34,797,717 | 3.13427 |
| nibble_swap | 343,500,214 | 30.22150 |

Total native time: 66.16594 seconds. No overlapping prefix counts are added.

The model is the pinned libmcrypt Blowfish-compat block primitive with the raw seven-byte key `Zombies`, CFB8, ASCII-zero IV `3030303030303030`, and a fixed global bijection from the sixteen displayed hex symbols to nibbles. The endpoint admits ASCII TAB/LF/CR/32..126 and complete UTF8 sequences E2 80 93/94/98/99, ending in state zero.

The source-controlled native search shares its DFS and endpoint logic with the earlier validated text engine. The compatibility adapter reverses bytes within each four-byte word around standard Blowfish encryption. Controls match all 200 supplied WASM block vectors (whose keys are sixteen bytes), exact Python DFS counters and mapping sets on synthetic fixtures, and full-byte CFB8 vectors. Separately, freshly compiled unchanged pinned libmcrypt C sources validate the actual seven-byte key and the word-reversal relationship. See [SOURCE_REPORT.md](SOURCE_REPORT.md), [README.md](README.md), and [TARGET.md](TARGET.md) for exact build instructions, dependencies and control boundaries.

The primary-source check includes a block taken from the already-known Rev7 prefix. That block check is not a Rev7 decryption or search, but the source check is not wholly synthetic. No target result is used to choose the adapter.

## Reproduction

From the isolated worktree used for this run:

```sh
cd /private/tmp/rev7-astra-20260909
python3 research/rev7-20260909-codex/hex_cfb/native_compat/run_target.py --selftest
python3 research/rev7-20260909-codex/hex_cfb/native_compat/run_target.py --run-target --target-output /tmp/bfcompat-target-reproduction.json --checkpoint /tmp/bfcompat-target-reproduction-checkpoint.json
```

The driver checks the frozen source, binary, controls and canonical input before evaluation. Binaries are not distributed. Rebuild using the recorded commands; a different compiler/platform may produce a different binary hash, which must be documented in a new reproduction gate instead of silently weakening the frozen gate. Original result and control files should be preserved.

## Exact artifacts

- `native_compat.cpp`: SHA-256 `c8527d2bf43494944475a20e0ffc8a99358243c8f188d394335af4ec9b0f8cb7`
- `controls.py`: SHA-256 `a10cb0636113aefcd1501bf7497a31899616ed288ef1848040a663723c761980`
- `controls.json`: SHA-256 `8105dafde232eb1d245e22a0224b34b5f863dfacfa5a223758a08a46db52a835`
- `source_check.py`: SHA-256 `3945fbebcc7ae8c8bd8df0b450590e149e7cbd86443bd9d92ddbae90ab91e69d`
- `source_check_reproduction.json`: SHA-256 `123724d5575fa7c2be2868d8218f774f775a395eae693e2049caa703eee47295`
- `run_target.py`: SHA-256 `6b737a29f89d83405983c50e27cccdc08a7f071f93e9b5ee135849453cb1150d`
- `target_gate.json`: SHA-256 `968566f55c14d47bb2677305c1f970a2a21e9754ade4b08bd5dda17eb8adf253`
- `target_results.json`: SHA-256 `ccb5483812db4dacfd37d711a59b9540b6a5074c3fb19617c0bdd3607605b9b4`

This finite exclusion does not cover other keys, IVs, ciphers, feedback modes, position-dependent symbol changes, different orientations, broader Unicode or binary endpoints. Rev7 remains unsolved.

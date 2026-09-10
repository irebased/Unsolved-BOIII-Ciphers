# Blowfish all-IV global-hex mapping results

**Identity:** ASTRA.

The preregistered eight-cell run completed without reaching any one-billion-node cap. Every standard Blowfish and historical Blowfish-compat orientation exhausted its full global sixteen-symbol bijection space and retained no strict-FSA survivor. Each cell has certificate weight `16! = 20,922,789,888,000`, zero uncovered mapping weight, and `certificate_complete=true`.

| Cipher | Orientation | Accepted DFS nodes | Native seconds | Survivors |
|---|---|---:|---:|---:|
| Blowfish | forward | 295,675,566 | 137.679 | 0 |
| Blowfish | full hex reverse | 295,490,770 | 134.604 | 0 |
| Blowfish | byte reverse | 295,736,813 | 133.919 | 0 |
| Blowfish | nibble swap | 295,835,162 | 137.242 | 0 |
| Blowfish compatibility | forward | 295,727,380 | 148.297 | 0 |
| Blowfish compatibility | full hex reverse | 295,590,429 | 145.511 | 0 |
| Blowfish compatibility | byte reverse | 295,634,705 | 144.264 | 0 |
| Blowfish compatibility | nibble swap | 295,749,507 | 148.519 | 0 |

Across all cells, the solver entered 2,365,440,332 accepted DFS nodes and made 21,643,489,230 ECB calls in 1,130.035 native seconds. The run used one process and completed from its initial invocation without restart.

The finite exclusion applies to the canonical 546-byte stream under the four registered orientations, raw seven-byte `Zombies`, standard or historical-compatible Blowfish CFB8, any external eight-byte IV, and one fixed global bijection from displayed hexadecimal symbols to nibble values. The necessary A105 byte filter applies to all IV-independent suffix bytes; terminal mappings must also satisfy the strict five-sequence UTF-8 FSA from possible initial states `{0,1,2}` to terminal state zero. It does not cover other keys, modes, transforms, alphabets, per-position mappings, or framing that changes which bytes form the CFB8 stream.

The target ledger is `target_results.json`, SHA-256 `dffebff216727736c2b21b58a3dfc75576b7798375603a0d6bc8ee67338d83fc`. Its frozen gate is SHA-256 `507f5c9d3f0a489ca612bfaf1600c9c3de91f844208540962b8a087274204a2b`.

The portable default verifier checks the result and gate hashes, every published source artifact, the recorded source/binary relationship in `native_build.json`, canonical extraction and orientation hashes, independently recomputed deterministic search geometry, the exact Cartesian cell set, stored native certificate fields, and aggregate totals. This is structural and accounting verification of the frozen ledger; it does not repeat the 2,365,440,332-node DFS. The local executable is machine-specific and need not be published or present. An optional flag checks it when available:

```text
python3 -S -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/verify_results.py
python3 -S -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/verify_results.py --check-local-binary
```

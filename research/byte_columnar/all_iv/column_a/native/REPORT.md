# Native columnar-A synthetic control report

**Identity:** ASTRA

## Outcome

All native controls passed without reading or evaluating Rev7.

The native DES, standard Blowfish, and Blowfish-compat primitives matched 96 independent ECB vectors. Each backend also matched a complete 256-byte CFB8 construction and decrypted it exactly. Standard DES and Blowfish additionally matched PyCryptodome `MODE_CFB` with `segment_size=8`; Blowfish-compat matched both the temporarily compiled unchanged historical C primitive and the independently verified word-reversal relation.

Three complete width-9 scans each examined all `P(9,8)=362,880` first-eight tuples and matched the frozen Python reference's exact ordered survivor-prefix and ninth-candidate sets:

| Backend | Survivor prefixes | Rejected prefixes | Distinct nonzero masks | Native seconds |
|---|---:|---:|---:|---:|
| DES | 4,223 | 358,657 | 9 | 0.0412356 |
| Blowfish | 4,352 | 358,528 | 9 | 0.0284577 |
| Blowfish-compat | 4,175 | 358,705 | 9 | 0.0304894 |

Each complete scan has both rejection and survival, retains its planted true tuple and ninth rank, and exactly partitions `9!` completion weight.

The additional exact 1,000-prefix comparisons use two-row public synthetic inputs, so more than one unused ninth rank can remain:

| Width | Rejected | Survivors | Multiple-candidate survivors |
|---|---:|---:|---:|
| 10 | 718 | 282 | 52 |
| 13 | 415 | 585 | 209 |
| 14 | 403 | 597 | 273 |

Native and Python agree on every ordered survivor and candidate set, all counters, the standard FNV-1a digest, and factorial cap accounting. Seven malformed-input cases were rejected.

## Bounded performance sample

A public fixture consists of 546 bytes from `random.Random(0xC01A2026)` and 546 calls to `randrange(256)`; its complete hex and SHA-256 are in `native_controls.json`. DES examined the first 1,000,000 lexicographic prefixes at each width:

| Width | Rows | Block calls | Seconds | Prefixes/s | Linear full-prefix estimate |
|---|---:|---:|---:|---:|---:|
| 13 | 42 | 3,136,516 | 0.241921 | 4,133,580 | 12.55 s |
| 14 | 39 | 3,191,810 | 0.256336 | 3,901,130 | 31.04 s |

These are capped, count-only measurements. The exact rejected, unresolved, and unexamined weights partition `13!` and `14!`. The full-time figures are linear projections from one synthetic prefix sample; early stopping and host performance can differ.

## Reproduction and provenance

```text
clang++ -std=c++17 -O3 -Wno-deprecated-declarations $(pkg-config --cflags openssl) research/byte_columnar/all_iv/column_a/native/native.cpp $(pkg-config --libs openssl) -o research/byte_columnar/all_iv/column_a/native/native_search
python3 -B research/byte_columnar/all_iv/column_a/native/native_controls.py
```

Frozen hashes:

- `native.cpp`: `960cdbaf643ca531728e2c6eeb337a5834842de9773c3a256319e9720bef1b07`
- `native_controls.py`: `a86afa2cb63c42e2304aae9750d8017e14ee558a9d2c1f2f7011c26ec9b69540`
- `native_controls.json`: `7b29daceb19899a6de3ad21954a0793513d324064c0bb169f66683f248ce5fb3`
- accepted proof `controls.json`: `2fb68eff8b80fb120ca972a29ead64268f03057c10c00156fd49152e0cf62bea`
- frozen Python `core.py`: `1deda1788e9d9a49140325c7e0f7ce3eb53aa7d05e8e44590be4076da0bae472`
- accepted compatibility build helper: `6c0ab4888febcf87d45515bd4ad8b34f11a85edb05d0cb99ad1f75b8dd24f0aa`
- local test binary: `4ad339f8f5d88766317ef2b939c51d21628018635246bbaac45df8ed1b0218d4`

The local binary and temporary compatibility-library hashes are machine evidence. The ledger records compiler, OpenSSL and PyCryptodome versions, the exact host and portable build commands, reviewed native-source hashes, historical Blowfish source hashes, and the temporary compatibility build invocation.

## Limits

This establishes implementation correctness and approximate synthetic throughput only. It adds no target driver or result. It does not test Rev7, recover a column order, IV, or plaintext, add cipher/key/mode contexts, or turn a surviving prefix into a solution.

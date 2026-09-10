# FABLE cascade3 dependency completion audit

Identity: **ASTRA**.

The three newly exposed files were captured byte-for-byte:

| File | Bytes | SHA-256 |
|---|---:|---|
| `cascade/scan.js` | 6,175 | `a4922fa692dce40ca69df76073f7399deb35396faec0bc650cbbc1be10d5872d` |
| `cascade3/plant3_hex.txt` | 664 | `ed8bc54ce3b752eaf93d09c35d577ba0565539a61b90354e86d501f352499147` |
| `cascade3/plant3_plaintext.txt` | 332 | `b3497dec7d217579eb3c2b60207a22ff61345f179046dfbe191babf69e709574` |

The capture also includes the referenced scan, cascade library, dictionary helper, UTF-8 gate, and the exact `mcrypt.js`/`mcrypt.wasm` runtime needed for a planted replay. Source and result hashes are recorded in `audit.json`.

## Exact registered search

`cascade/scan.js` builds 46 layer options as the Cartesian product of 23 registry ciphers and the literal key strings `Zombies` and `ZOMBIES`, in cipher-major/key-minor order. The ciphers are 3-way, Blowfish, Blowfish-compat, CAST-128, CAST-256, DES, Triple-DES, GOST, Loki97, RC2, Rijndael-128/192/256, SAFER-64/128, SAFER+, Serpent, Twofish, XTEA, Enigma, Panama, ARCFOUR, and WAKE.

Block ciphers use wrapper mode integer 0, identified by the source as CFB8, and an ASCII `0` IV repeated to the block size. The literal seven-byte key is passed for every cipher except Loki97, which receives an explicit 32-byte zero-backed buffer with the literal prefix. The four stream ciphers use their stream entry points, so block mode and IV do not apply. Block sizes are captured per cipher in the machine ledger.

The sweep uses four hexadecimal orientations: displayed, full-symbol reverse, byte-pair reverse, and nibble swap. At the input and each of three layer boundaries it optionally applies `reverseBuf`, for 16 flag combinations. `reverseBuf` reverses Unicode codepoints when the entire buffer is valid UTF-8 and otherwise reverses raw bytes. The final score skips the last cipher’s block size, or zero bytes for a stream cipher.

The theoretical and reported counts agree exactly:

- `46^3 × 16 = 1,557,376` leaves per orientation;
- `4 × 1,557,376 = 6,229,504` full leaves;
- every reported orientation has 1,557,376 leaves;
- both negative and Revelation histograms sum to 6,229,504 in both recorded dimensions.

Because `scan3.js` catches cipher failures and skips their branches, equality to the theoretical leaf count is material evidence that the reported runs skipped no leaves for those inputs. It does not independently reproduce their cryptographic outputs.

## Planted replay

The one authorized planted recipe was replayed through the captured WASM runtime:

```
ciphertext
  decrypt serpent / Zombies
  reverseBuf
  decrypt blowfish / Zombies
  decrypt twofish / Zombies
plaintext
```

It recovers the exact 332-byte plaintext, SHA-256 `b3497dec7d217579eb3c2b60207a22ff61345f179046dfbe191babf69e709574`. Applying the inverse encrypt recipe rebuilds the exact 332-byte ciphertext, SHA-256 `85ef5c3572b1581c6900e0840dc2e559569712870e77d266d7694b97f3f02c81`. Every intermediate remains 332 bytes, confirming CFB8 length preservation and no padding or alignment truncation on this path. Skipping the final Twofish block reproduces `{longestRun:316, validCount:316, tailLen:316}`. The stored result reports this path at rank 1 with two equal-score leaves.

The recorded full result is internally consistent with a Revelation maximum run of 21 and negative-control maximum 23. These values, ranks, and histograms were inspected but the 6,229,504-leaf searches were not rerun.

## Remaining replay gap

At capture time, `run3.js` referenced `cascade/negative_seed_hex.txt`, but that file was absent and was not captured. Therefore the negative histogram cannot yet be independently regenerated. The Revelation input is available as 1,093 bytes including a newline, SHA-256 `1b1d340ff7de53776c737d0d34ba7438d591679fe0f27efc56856f28c8648827`; whitespace stripping and uppercase normalization produce the 1,092-symbol canonical SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`. No target sweep was performed in this audit.

## Base64-reading lane inventory

The audit froze metadata for thirteen files that were readable under `/private/tmp/rev7-fable-20260909/b64read` at capture time: `assemble.js`, `make_targets.js`, `out_t0.json`, `out_t1.json`, `out_t2.json`, `plant_b64.txt`, `plant_note.json`, `plant_plaintext.txt`, `readings.js`, `readings.json`, `run.js`, `targets.json`, and `worker.js`. Their sizes and SHA-256 values are frozen in `capture/b64read_inventory.json` and copied into `audit.json`; default verification no longer reads the mutable external mirror. A separate semantic audit is in `coverage/fable_b64read_source_audit/`. This report retains only its historical inventory scope.

## Reproduction

From the repository root:

```sh
node research/rev7-20260909-codex/coverage/fable_cascade3_completion_audit/controls.js
python3 -B research/rev7-20260909-codex/coverage/fable_cascade3_completion_audit/audit.py
```

The Node command performs only the single planted decrypt/encrypt replay. It requires the captured `old-ciphers/js/mcrypt.js` and exact 211,879-byte `mcrypt.wasm` (SHA-256 `60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7`), sourced from old-ciphers commit `7c43c6ae65f49bd7504494d9ca3c55ce2e2496b6`; both are included in this package. The Python command reruns that control, verifies every captured source and b64read inventory hash, and checks stored-result accounting. Neither command starts the exhaustive target or negative sweep.

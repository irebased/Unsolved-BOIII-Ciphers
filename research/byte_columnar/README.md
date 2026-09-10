# ASTRA byte-column permutation proof of concept

This directory contains synthetic controls only. It does not load or evaluate the Rev7 ciphertext and has no target driver.

The model is AES-128 CFB8 with key bytes `Zombies` followed by nine NUL bytes and IV `30303030303030303030303030303030`. Plaintext accepts TAB, LF, CR, ASCII 32–126, and exactly five UTF-8 sequences: `E2 80 93`, `E2 80 94`, `E2 80 98`, `E2 80 99`, and the Rev9-supported ellipsis `E2 80 A6`. The FSA must finish in its normal state.

## Transform definitions

Both variants use FABLE's convention: `order[k]` is the natural column emitted at observed rank `k`.

- Variant A writes the pre-transposition bytes row-major and emits contiguous column chunks in `order`. During inversion, assigning the observed chunk for natural column `c` exposes the next byte of the reconstructed first row. The DFS decrypts that byte immediately. After all columns are assigned, it reconstructs and validates the remaining rows.
- Variant B treats the pre-transposition bytes as contiguous natural-column chunks and emits rows whose columns are visited in `order`. During inversion, assigning an observed rank to the next natural column exposes an entire strided observed column, so the DFS decrypts that full chunk immediately.

The fixed 12-byte inverse fixtures match FABLE's `byteTranspositions.js` and `transpositions.js` exactly for width 3 and order `[2,0,1]`. The frozen source hashes are recorded in `controls.json`.

A node is an accepted-prefix DFS entry, including the root and complete entries. When a new assignment makes the plaintext FSA fail, the branch charges `factorial(unassigned columns)` complete permutations. A valid complete permutation charges one. For an uncapped root search, rejected weight plus terminal weight must equal `width!`. For a capped search, the recorded weight is only a proven lower bound; the cap-one control checks this behavior.

## Control evidence

The controls compare Python prefix DFS, native DFS, and independent naive complete-permutation enumeration at widths 3–6 for both variants. The survivor sets, raw counters, and factorial certificates agree exactly.

A deterministic 546-byte plant contains all five permitted UTF-8 punctuation sequences. At widths 13 and 14, both variants recover the nontrivial planted order as the unique solution and exhaust the full factorial space under the 10,000,000-node control cap:

| Width | Variant | Nodes | Certificate |
|---:|:---:|---:|---:|
| 13 | A | 416,773 | `13!` |
| 13 | B | 14 | `13!` |
| 14 | A | 2,157,257 | `14!` |
| 14 | B | 15 | `14!` |

The timing values in `controls.json` are local measurements, not target-runtime guarantees. A deterministic random 546-byte control also completes all four certificates with zero survivors. The pinned solved Rev9 control proves that the former four-sequence FSA rejects its original `E2 80 A6` ellipsis while this five-sequence FSA accepts the complete plaintext; truncated `E2` and `E2 80` endings are rejected.

## Reproduction

From `/private/tmp/rev7-astra-20260909`:

```sh
clang++ -std=c++17 -O3 \
  -I/opt/homebrew/opt/openssl@3/include \
  research/byte_columnar/native.cpp \
  -L/opt/homebrew/opt/openssl@3/lib -lcrypto \
  -Wl,-rpath,/opt/homebrew/opt/openssl@3/lib \
  -o research/byte_columnar/native_search
python3 -B research/byte_columnar/controls.py
```

`controls.py` refuses to overwrite an existing `controls.json`. Reproduce in a fresh copy or preserve and remove the old output deliberately.

Frozen artifacts:

- `core.py`: `149eebf8b729c2ea66a1c1fc22172fad38282daae4386beb6494535cb08d6662`
- `native.cpp`: `643acda025697a1ff30d92d198444dea823d654b11825c87e5843657123bda76`
- `native_search`: `e86ca412592c807ea0440f17de7f8653c9cbfde9a352f722da46c1f5195cc31d`
- `controls.py`: `dbdfc1fdc3d110585d391f82ff03dbd737c89b644965fc377c873b82d4c4b0a9`
- `controls.json`: `641dd0a14db911050631e47579e4905bf38715a1bb22c1453e52b3ce1635afb2`

Identity: ASTRA.

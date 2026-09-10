# Native DES IV-independent solver controls

Identity: **ASTRA**. Synthetic controls only. Target evaluated: **false**; no Rev7 file was read.

`native.cpp` implements the accepted Python feasibility model with OpenSSL DES and the fixed key `Zombies` plus one NUL byte. It mirrors the Python geometry order and tie breakers, builds activation lists after applying any seed mapping, evaluates each nine-byte window when its last unseeded display symbol becomes bound, stops all ancestors after the node cap, and charges rejected subtrees by the factorial of entries still unassigned.

The complete-mapping endpoint is implemented independently as a native state-set bitmask. It begins with possible suffix states `{0,1,2}` and accepts only terminal state zero after TAB/LF/CR, ASCII 32..126, or complete `E2 80 93/94/98/99/A6` sequences. Native boundary controls accept valid complete strings and valid initial continuation completion, while rejecting truncated `E2`, truncated `E2 80`, and wrong third byte `A5`.

OpenSSL ECB output for block `0001020304050607` is checked directly against PyCryptodome. PyCryptodome `MODE_CFB` with `segment_size=8` is then compared to native CFB8 under arbitrary IV `80ff017ec355aa19` and ASCII-zero IV. In both cases, independently recomputing `C[i] XOR DES(C[i-8:i])[0]` recovers every plaintext suffix byte for `i>=8`.

The four-unknown synthetic plant exhausts all 24 mappings. Native and optimized Python results match all counters, factorial fields, survivor maps, and full suffix bytes. Passing the default 16-symbol order explicitly produces the same results and validates the optional order interface; no alternate order is selected here.

The full-sixteen-symbol 250,000- and 1,000,000-node prefixes exactly match optimized Python counters and survivor sets. Both remain capped and incomplete. Native performance was:

| Cap | Native seconds | Nodes/second | ECB calls | ECB calls/second | Python seconds |
|---:|---:|---:|---:|---:|---:|
| 250,000 | 0.124877 | 2,001,970 | 1,795,393 | 14,377,291 | 4.635188 |
| 1,000,000 | 0.523662 | 1,909,629 | 7,178,308 | 13,707,903 | 18.816444 |

These are synthetic host measurements. They estimate implementation cost but do not guarantee target runtime. The controls make no completeness or target claim.

## Build and reproduce

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/iv_independent/solver
clang++ -std=c++17 -O3 -Wno-deprecated-declarations native.cpp -o native   -I/opt/homebrew/Cellar/openssl@3/3.6.3/include   -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto   -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib
python3 -B native_controls.py
```

The native search interface is `native CAP DISPLAYHEX [SEED] [ORDER16HEX]`. The optional order is rejected unless it contains every hexadecimal symbol exactly once. `native_controls.py` refuses an existing `native_controls.json`. Any target driver and budget require separate review and authorization.

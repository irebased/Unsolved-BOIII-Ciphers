# Native ASCII and historical-punctuation CFB8 DFS controls

Identity: ASTRA. Target evaluated: false.

This is a separate synthetic-only adaptation of the accepted native DFS. Its endpoint accepts TAB, LF, CR, ASCII 32 through 126, and exactly UTF-8 `E2 80 93/94/98/99`. Endpoint states 1 and 2 are rejected at end-of-stream and contribute their remaining factorial weight to `rejected_completion_weight`.

Build and run:

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/hex_cfb/native_text
clang++ -std=c++17 -O3 -Wno-deprecated-declarations native_text.cpp -o native_text \
  -I/opt/homebrew/Cellar/openssl@3/3.6.3/include \
  -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto \
  -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib
python3 -B controls.py
```

Controls retain all-byte native/manual/PyCryptodome CFB8 equivalence for AES128, raw-seven-byte Blowfish, and DES. Complete four-unknown searches compare every statistic, factorial weight, survivor mapping, and full plaintext to Python. A mixed punctuation plant exercises every accepted multibyte ending. Dedicated `E2` and `E2 80` fixtures must reach the end in a nonterminal state and be rejected. A repeated high/low display symbol exercises the same-symbol assignment branch.

The deterministic full-16-symbol plant is compared with Python at 250,000 and 1,000,000 nodes. Those controls certify equal capped prefixes only. Their incomplete certificate does not claim recovery or exhaustive coverage.

No Rev7 ciphertext is opened or evaluated. The target driver is deliberately absent.

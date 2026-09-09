# Native global-hex-map CFB8 DFS controls

Identity: ASTRA. This directory contains a synthetic-only C++17 implementation
of the Python `prototype.backtrack` search. It never opens the Rev7 ciphertext.
The endpoint used by the controls is the 69-byte Base64 set: ASCII letters,
digits, `+/=`, space, TAB, LF, and CR.

The native search preserves the Python candidate order, same-symbol assignment,
seeded maps, factorial subtree weights, and node-cap behavior. A node is an
accepted-prefix DFS entry, including root and terminal. After the cap is first
reached, recursive calls return immediately while existing ancestor loops still
test remaining choices and count plaintext rejections, exactly as the reference
does.

Build and reproduce:

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/hex_cfb/native
clang++ -std=c++17 -O3 -Wno-deprecated-declarations native_dfs.cpp -o native_dfs \
  -I/opt/homebrew/Cellar/openssl@3/3.6.3/include \
  -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto \
  -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib
python3 -B controls.py
```

`controls.py` refuses to overwrite `controls.json`. Remove or rename that
synthetic result before an intentional reproduction. The frozen control checks
native CFB8 against both manual Python and PyCryptodome CFB8 for all byte values
and all three registered ciphers. It then compares every reported DFS counter,
factorial certificate, mapping, and plaintext with Python on seeded four-unknown
complete searches for AES128, raw-seven-byte Blowfish, and DES. Finally it
compares exact capped prefixes at 250,000 and 1,000,000 nodes on a deterministic
546-byte full-16-symbol AES/Base64 plant.

CommonCrypto accepted the registered AES and DES keys but rejected the raw
seven-byte Blowfish key with status -4310. The selected backend is the already
installed OpenSSL 3.6.3 public low-level API. `BF_set_key` receives exactly
seven bytes, preserving the registered model. No padding or repeated-key
substitution is used.

On this host the native 1,000,000-node control took about 0.09 seconds, versus
about five seconds for the combined Python-reference plus native comparison.
The capped certificate is intentionally incomplete; the seeded controls each
certify all 4! mappings with rejected plus terminal weight equal to 24.

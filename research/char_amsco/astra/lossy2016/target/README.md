# Lossy AMSCO `2016` target driver (inert)

Exact 16-context scope: legacy key `2016`, start `21`, natural ciphertext length 819 bytes, four canonical hex orientations, DES/AES-128 with the fixed Zombies keys, and fixed NUL/ASCII-zero IVs. Plaintext is A-Z plus SPACE. Every complete frontier solution is retained. Either registered cap makes a context explicitly incomplete.

Every survivor is independently decrypted and re-encrypted with PyCryptodome CFB8 and passed through the pinned legacy source port to reproduce the oriented 1,092-character observation. Synthetic controls traverse that same path for all 16 contexts and invert every orientation.

Default execution hashes inputs only. Target execution requires a future immutable gate and separate root GO.

```sh
python3 -B research/char_amsco/astra/lossy2016/target/driver_controls.py
python3 -B research/char_amsco/astra/lossy2016/target/run_target.py
```

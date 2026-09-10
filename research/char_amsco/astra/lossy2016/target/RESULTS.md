# ASTRA lossy-AMSCO `2016` target result

The preregistered 16-context scan completed once. Every context exhausted its exact A-Z-plus-SPACE frontier without reaching either cap, and there were zero complete plaintext/ciphertext solutions. Fifteen contexts reject at natural ciphertext byte offset 0. `forward|aes128|nul` retains one path at offsets 0 and 1 and rejects it at offset 2.

The finite scope was the literal legacy key `2016`, historical start `21`, a natural 819-byte ciphertext masked by the 1,092-character displayed stream, four canonical hex orientations, DES/AES-128 with fixed Zombies keys, and fixed NUL/ASCII-zero IVs. This does not address other malformed keys, alphabets, ciphers, IVs, or framing.

The saved result is 12,967 bytes, SHA-256 `1bc9a98a2af2f6d3f2f9c5c2adde5c87c78f7327840a8de7ba39407cf4676995`. Gate SHA-256 is `da753b01353e65fc5d81e6905ab5a0b9747be0091fbbc6c7bd0a20336f24f9a7`; driver SHA-256 is `036ab0f597906ca90699d63f4ea42033030e21a1fca28476e2746b735144ae4c`.

`verify_results.py` independently reconstructs the four observed orientations and `FF,0F,F0` masks, replays every prefix through its first empty frontier, checks all failed byte candidates, and binds the exact ordered Cartesian grid, source hashes, cap/completeness counters, and zero-solution result. No full target search is repeated.

```sh
python3 -B research/char_amsco/astra/lossy2016/target/verify_results.py
```

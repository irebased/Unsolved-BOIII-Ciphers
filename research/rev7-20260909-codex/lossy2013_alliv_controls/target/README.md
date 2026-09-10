# Inert lossy `2013`/`2014` all-IV target driver

This registered candidate scope has four contexts: the canonical 1,092-character observation under forward, full-hex-reverse, byte-reverse, and per-byte nibble-swap orientations. Each context uses DES CFB8 with `Zombies\0` and enumerates every one of the 4,096 compatible first-eight ciphertext registers. This represents every original eight-byte IV without claiming to recover that IV or the first eight plaintext bytes. The searched suffix is exactly bytes 8 through 654 and permits printable ASCII `0x20..0x7E`.

The search preserves every terminal full-ciphertext and plaintext-suffix completion. Its 100,000 live-frontier cap applies per sequential root; the 5,000,000 accepted-state cap applies globally within each orientation. A cap is INCOMPLETE with exact completed, partial, and unexamined root accounting.

Synthetic controls exercise the exact target driver across all four orientations with a 655-byte plant and independently validate every terminal completion. Default driver execution hashes the MDX and dataset but does not extract or evaluate their ciphertext. An immutable gate tied to an external preregistration and a separate GO are required before `--run-target`.

Identity: ASTRA.

# One-billion-node extension result

Identity: ASTRA.

Extension ledger SHA-256: `98943e234cf29487f9c800c9f70a53ae718257284f7c2554bcbc927ba072dd71`.

All six fresh-root traversals completed before the registered 1,000,000,000-node cap. Every row has rejected plus terminal factorial weight equal to 16!, and no terminal survivor was found.

| Cipher | Orientation | Status | Nodes | Certificate weight | Seconds | Survivors |
|---|---|---:|---:|---:|---:|---:|
| aes128 | forward | complete | 337295196 | 20922789888000 | 23.092200 | 0 |
| aes128 | nibble_swap | complete | 338902415 | 20922789888000 | 23.397500 | 0 |
| blowfish | forward | complete | 343320117 | 20922789888000 | 28.292500 | 0 |
| blowfish | nibble_swap | complete | 331914860 | 20922789888000 | 27.744600 | 0 |
| des | forward | complete | 333163501 | 20922789888000 | 36.249400 | 0 |
| des | nibble_swap | complete | 333642755 | 20922789888000 | 36.063000 | 0 |

Total native time recorded by the six rows: 174.839200 seconds.

## Finite conclusion

Combined with the previously completed reverse and byte-reverse rows, all twelve registered cipher/orientation cells have now exhausted the full 16! global hexadecimal-symbol mapping space. No mapping produces a complete plaintext accepted by the exact ASCII-plus-four-UTF-8-punctuation endpoint under the registered CFB8 recipes.

This exhausts only the frozen model: AES128 with NUL-padded `Zombies`, raw-seven-byte Blowfish `Zombies`, or DES with NUL-padded `Zombies`; ASCII-zero IV; CFB8; the four canonical orientations; one global bijective hexadecimal-symbol map; and terminal FSA state zero. It does not exclude other keys, IVs, modes, transformations, repairs, encodings, or cipher families.

No further node-cap extension is needed for this registered grid.

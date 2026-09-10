# ASTRA byte-column target result

Identity: ASTRA. Status: target complete.

The preregistered 16-cell run completed once with the frozen driver and gate. All 16 cells exhausted their full column-permutation spaces, none reached the 10,000,000-node cap, and none produced a plaintext accepted. Total native time reported by the native cells was 1.461436632 seconds.

The finite result is:

- AES-128 CFB8;
- key `Zombies` followed by nine NUL bytes;
- ASCII-zero IV `30303030303030303030303030303030`;
- byte-column widths 13 and 14;
- FABLE-compatible variants A and B;
- orientations `forward`, `full_hex_reverse`, `byte_reverse`, and `nibble_swap`;
- strict TAB/LF/CR, ASCII 32–126, plus only `E2 80 {93,94,98,99,A6}`.

No permutation in this exact scope yields a complete permitted plaintext. This does not cover other ciphers, keys, IVs, widths, ragged layouts, transposition definitions, or text endpoints.

| Orientation | Width | Variant | Nodes | Rejected full candidates | Certificate | Capped | Survivors |
|---|---:|:---:|---:|---:|---:|:---:|---:|
| forward | 13 | A | 296,204 | 23,410 | 13! | no | 0 |
| forward | 13 | B | 1 | 0 | 13! | no | 0 |
| forward | 14 | A | 679,296 | 54,246 | 14! | no | 0 |
| forward | 14 | B | 1 | 0 | 14! | no | 0 |
| full_hex_reverse | 13 | A | 333,025 | 26,408 | 13! | no | 0 |
| full_hex_reverse | 13 | B | 1 | 0 | 13! | no | 0 |
| full_hex_reverse | 14 | A | 2,518,313 | 199,404 | 14! | no | 0 |
| full_hex_reverse | 14 | B | 1 | 0 | 14! | no | 0 |
| byte_reverse | 13 | A | 640,166 | 50,538 | 13! | no | 0 |
| byte_reverse | 13 | B | 1 | 0 | 13! | no | 0 |
| byte_reverse | 14 | A | 999,851 | 78,764 | 14! | no | 0 |
| byte_reverse | 14 | B | 1 | 0 | 14! | no | 0 |
| nibble_swap | 13 | A | 362,837 | 28,618 | 13! | no | 0 |
| nibble_swap | 13 | B | 1 | 0 | 13! | no | 0 |
| nibble_swap | 14 | A | 1,653,387 | 130,810 | 14! | no | 0 |
| nibble_swap | 14 | B | 1 | 0 | 14! | no | 0 |

For each cell, `rejected_weight + terminal_weight = width!`; terminal weight is zero throughout. Variant B rejects every root assignment after decrypting its exposed full column, explaining its one-node certificates. Variant A explores accepted first-row prefixes and rejects the complete reconstruction when necessary.

Run command, from `/private/tmp/rev7-astra-20260909`:

```sh
python3 -B research/byte_columnar/run_target.py --run-target
```

Evidence:

- target results SHA-256: `90902426dbe074a13098e54f136e3ee43677d6da3fb9b6f0ee525b7958c6d8a9`
- driver SHA-256: `1aada314fca7d765a0e9214bef8af15b9a7d74e74fca22eb7c24d9d7b663e1ed`
- gate SHA-256: `a5aa0329e3b65ca935d7366c2aa2281048bc377e1dbeb746fc8f7a6ee5c22bbb`
- canonical MDX SHA-256: `085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91`
- extracted canonical ciphertext SHA-256: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

There were no survivors, so the registered independent survivor replay had no cases to evaluate.

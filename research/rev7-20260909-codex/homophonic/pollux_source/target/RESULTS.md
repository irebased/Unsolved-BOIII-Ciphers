# Pollux fixed-board target result

Identity: **ASTRA**

## Registered scope

The frozen target evaluated exactly 16 contexts:

- the two numeric Pollux boards exposed by the historical frontend: plain numeric and `createMulAlfa(..., 7)`;
- whole-decimal digit order unchanged or reversed;
- the four canonical hexadecimal orientations: forward, full hex reverse, byte reverse, and nibble swap.

Each complete 546-byte Rev7 orientation was converted through the registered whole-integer decimal route. No parity digit was inserted. Every full decimal digit string and mapped Morse string is retained in `target_results.json`.

The acceptance condition was the deliberately broad necessary language: a nonempty sequence of any of the 44 literal historical Morse-table tokens, separated by exactly one separator, with no leading or trailing separator. This is a safe superset of frontend-reachable plaintext. It is not a plaintext scorer and does not emulate every PHP normalization detail.

## Result

All **16 of 16** registered contexts fail the necessary language condition. There are no accepted contexts.

| Board | Decimal direction | Hex orientation | First failure |
|---|---|---|---|
| numeric_plain | identity | forward | empty token at offset 6, digit `1` |
| numeric_plain | identity | full_hex_reverse | invalid token `..--.`, offsets 0..5 |
| numeric_plain | identity | byte_reverse | empty token at offset 7, digit `2` |
| numeric_plain | identity | nibble_swap | leading separator at offset 0, digit `1` |
| numeric_plain | digit_reverse | forward | invalid token `..--`, offsets 0..4 |
| numeric_plain | digit_reverse | full_hex_reverse | empty token at offset 5, digit `2` |
| numeric_plain | digit_reverse | byte_reverse | empty token at offset 6, digit `1` |
| numeric_plain | digit_reverse | nibble_swap | empty token at offset 7, digit `0` |
| numeric_mul7 | identity | forward | leading separator at offset 0, digit `4` |
| numeric_mul7 | identity | full_hex_reverse | leading separator at offset 0, digit `7` |
| numeric_mul7 | identity | byte_reverse | invalid token `..-----.`, offsets 0..8 |
| numeric_mul7 | identity | nibble_swap | empty token at offset 2, digit `4` |
| numeric_mul7 | digit_reverse | forward | invalid token `..--`, offsets 0..4 |
| numeric_mul7 | digit_reverse | full_hex_reverse | leading separator at offset 0, digit `4` |
| numeric_mul7 | digit_reverse | byte_reverse | invalid token `----`, offsets 5..9 |
| numeric_mul7 | digit_reverse | nibble_swap | empty token at offset 7, digit `0` |

Failure classes are: **7 empty-token**, **4 leading-separator**, and **5 invalid-token** witnesses. All 16 integer conversions re-encrypt exactly to their registered oriented hexadecimal inputs.

This is a finite exclusion of these two source-backed numeric UI boards under the registered whole-integer conversion and four orientations. It does not exclude the historical alphabetic or mixed UI boards, arbitrary Pollux maps, other radix/framing schemes, or unrelated cipher families.

## Artifacts and reproduction

- `target_results.json`: 58,224 bytes; SHA-256 `05ebcee30a780e7efa07008f8d6f4cb79c2150d5aef1591c343e239b131a0969`
- `target_gate.json`: SHA-256 `dc1f7a11cd9b876b1119da9c90138409873486678f669753b73315c84dfe7a5e`
- `run_target.py`: SHA-256 `4871d10c2339ac27f390dbda79e750c83b893c275f3700007013dbcfed0ba029`
- `controls.py`: SHA-256 `67d4455153a3d1caead4d6a57686dd29bbbd59ebd57b6eb051a4513272bf4d84`
- `controls.json`: SHA-256 `18841da097e68c8e0416dabaf98e115147a1b0dd09e2dddcf4ec13ee21b2ed03`
- `driver_controls.py`: SHA-256 `b0d494c16d54d384b2eeeb945db790eb0daf3337ffc43a8f80ed1105716da571`
- `driver_controls.json`: SHA-256 `1aa1e76338fa128b4403eae16081588ba332c0a5bd2374973a2739e502969d28`

Registered one-time execution:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/target/run_target.py --run-target
```

Portable result verification:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/target/verify_results.py
```

The verifier reconstructs the fixed 16-context Cartesian grid, canonical orientations, decimal conversions, literal boards, split witnesses, and the regular-expression form of the broad 44-token grammar. It also checks the pinned source, control, driver, gate, canonical-input, and result hashes. This is an independent accounting and grammar replay over the retained outputs, not a new or expanded target search.

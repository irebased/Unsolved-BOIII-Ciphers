# ASTRA Pollux source audit and numeric-board controls

This package pins the historical CrypTool Pollux source at commit `4fc443f0d87c0e86815695a47ab2d6174c725f82`, corrects the earlier incomplete audit, and supplies synthetic controls for the two source-fixed numeric boards. It does not read or evaluate Rev7 and contains no target driver.

## Exact frontend behavior

The form exposes only three checkboxes: `num`, `alf`, and `misch` at form lines 31-33. There is no freeform Pollux key field. The frontend reads those values at default-tool lines 29-31, selects one of three symbol domains at lines 39-46, optionally applies `createMulAlfa(...,7)` at line 49, and slices the selected alphabet into separator, dash, and dot classes at lines 51-53.

The domains and class counts from `alfa_dat.php` are:

| Domain | Symbol order | separator / dash / dot |
|---|---|---:|
| Numeric | 0 through 9 | 3 / 3 / 4 |
| Alphabetic | A through Z | 8 / 8 / 10 |
| Mixed | A through Z, then 0 through 9 | 11 / 11 / 14 |

Each domain has an unmixed and multiply-by-7 board, so the UI exposes six boards total. When no boxes are submitted, line 43 first sets all three flags; the later independent condition at line 46 consequently selects the 36-symbol mixed domain, then line 49 applies multiplication by 7.

The two numeric boards are therefore exactly:

- Plain: separator `0,1,2`; dash `3,4,5`; dot `6,7,8,9`.
- Multiply by 7: separator `0,7,4`; dash `1,8,5`; dot `2,9,6,3`.

`encPollux` maps a Morse separator, dash, or dot to a random member of its corresponding class at function lines 7-26. `decPollux` maps class members back at lines 28-41. The six source-generated boards are disjoint partitions, although the low-level decoder itself does not reject an externally supplied overlapping assignment.

## Morse and normalization details

The frontend strips plaintext spaces at line 62, normalizes against `morse[0]` at line 77, calls `toMorse`, and trims its result at line 78. Thus a nonempty encoder-produced Morse stream has exactly one interletter separator and no leading or trailing separator.

The literal source table has 44 entries. Its zero label is the string `10`, not `0`; input digit zero is consequently removed by frontend normalization. The table's literal space entry has code `-...-`, but frontend spaces were already removed. Its quote label is `&quot;`, which a literal one-byte quote does not match. At the low-level `fromMorse` function, an unknown code can alias array index zero and yield A; the controls do not use that permissive decoder as a validity test.

For a conservative necessary condition, the controlled Morse grammar accepts every one of the 44 literal table codewords, including the frontend-unreachable entries. It requires a nonempty sequence of valid codewords, a maximum codeword length of six, and exactly one Morse-space separator between words. This safe superset avoids turning PHP normalization quirks into false hard negatives.

## Synthetic controls

The controls exhaust all 1,093 dot/dash/space strings of lengths zero through six and compare the production parser with a separately expressed regular-language oracle. They exercise seven nonempty normalized plaintext fixtures over both numeric boards, forward and digit-reversed decimal streams, and all four canonical hex orientations, for 112 exact whole-integer round-trips.

Digit zero belongs to the separator class in both numeric boards. Because the frontend trims the Morse stream, a valid nonempty numeric encoder output cannot begin or end with zero. Neither forward nor digit-reversed decimal orientation therefore loses a leading Pollux symbol when passed through whole-integer conversion. Separate deliberately invalid leading-zero examples demonstrate the actual lossy integer behavior. No parity zero is inserted: Pollux digits are single units rather than two-digit homophones.

A prospective target scope would contain only the two fixed numeric boards, two decimal directions, and four hex orientations, for 16 contexts. That scope has not been run or gated. Generic class assignments, radix-26, radix-36, and permissive `fromMorse` output are outside this control.

## Sources and reproduction

Unmodified source files and their SHA-256 values:

- `functions.pollux.php`: `3b49d000ad5352c37b49a83fb34b078d44c3f8045109ce5b9f4df0d6ef6ecb1c`; git blob `d3f3d0e1353241c167b20a9ce61a90131b2041c3`
- `default_tool.php`: `ca9f9ad05d3260203a1d8130ce4dc0b3da251cb845913e5985b45287fbd6224d`; git blob `4722f1511331a667dd6c36f560ef89f1d8e93e3f`
- `form.template`: `f359d01b0a4a19e3db7d83b78be5a4c7573e96476c2cdf741b8efd5450b8695a`; git blob `68c65fa4cc470c5dc918e58fff706b6ee3171dc9`
- Latin-1 `alfa_dat.php`: `4db1baed5abd8aa86e428db2bed579e9cc52930e9cd527e1cf57487fd43eda3a`; git blob `63a0f7fc0d67b481515ae2625ddb5137992ac049`
- `alfa_dat.php.base64`: `1020d8d7cdd0b69543ff924e9082d761e1149cc661fbe78e6f2792c32f8f7124`; decoding equals the Latin-1 source byte for byte

Control source SHA-256: `67d4455153a3d1caead4d6a57686dd29bbbd59ebd57b6eb051a4513272bf4d84`.

Control ledger SHA-256: `18841da097e68c8e0416dabaf98e115147a1b0dd09e2dddcf4ec13ee21b2ed03`.

The Latin-1 alphabet source is portable: verification always validates the pinned Base64 file and decodes it in memory, checking the exact raw SHA-256 and git-blob SHA-1. When a raw `alfa_dat.php` is present it must equal those decoded bytes; the registered controls explicitly exercised the forced Base64-memory route without moving the raw file.

Portable read-only verification:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/controls.py
```

Explicit regeneration refuses an existing path:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/controls.py --regenerate /tmp/astra-pollux-controls-new.json
```

Identity: ASTRA. Target evaluated: false.

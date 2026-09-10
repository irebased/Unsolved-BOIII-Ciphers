# FABLE Base64 tier-3 completion audit

Identity: **ASTRA**.

## Completed accounting

The supplied tier-3 files close the earlier source-capture gap. The exact JavaScript `readKeyFile` implementation splits on LF, drops only empty lines, and expands the four escapes `\\n`, `\\r`, `\\t`, and `\\\\`. Applying it to the three registered files yields:

| Input | Parsed entries | Unique within file |
|---|---:|---:|
| `keys_dict.txt` | 703,344 | 703,344 |
| `keys_lore.txt` | 636 | 636 |
| `keys_artifacts.txt` | 801 | 801 |

The concatenation has 704,781 entries. JavaScript's insertion-ordered `Set` removes 114 duplicates, leaving exactly **704,667** tier-3 keys. The 7,449,348-byte dictionary is stored losslessly as deterministic gzip; default verification bounds decompression, checks the original SHA-256 `a6a970dcd6335844976d2834e6279fece5ec687ce9a65e91f79056caa7532d91`, writes it only to a temporary directory, and calls the captured JavaScript parser itself.

The worker has 19 block ciphers × 4 modes plus 4 stream ciphers, or 80 contexts per key per target. Every tier's metadata must list the same seven target IDs in the registered order, and its result rows must contain exactly that unique ID set: five REAL readings, the one NEG, and the one POS. All seven tier-3 rows report exactly 56,373,360 trials and zero errors:

```
704,667 keys × 80 contexts = 56,373,360 per target
56,373,360 × 7 targets = 394,613,520 tier-3 trials
394,613,520 + 1,467,760 stored tier-0/1/2 trials = 396,081,280
```

All four stored tier files therefore account for the reported **396,081,280** trials exactly, with zero recorded worker errors. This audit checks stored accounting and endpoint values; it does not rerun the sweep.

The tier-3 positive row also retains the expected full scored-tail hit: UTF-8 longest run 803 at Twofish/CFB8/key `Zombies`, 56,373,360 trials, and zero errors. The earlier accepted Base64 audit cryptographically replayed that positive through both the direct primitive and captured worker path.

## Verdict inconsistency

`assemble.js` selects the maximum for each endpoint across all four tiers and compares it to the maximum from the single stored uppercase-hex negative. Reproducing that merge shows that every real reading exceeds the negative maximum on some of the 18 endpoints highlighted by `assemble.js`:

| Reading | Highlighted endpoints above negative maximum |
|---|---:|
| displayed | 7 |
| fullReversed | 6 |
| bytePairReversed | 7 |
| nibbleSwap | 9 |
| lowercased | 7 |

Consequently, the hard-coded verdict that “every real reading is at or below the restricted-alphabet negative control” is literally inconsistent with the stored results. For example, displayed exceeds the negative on UTF-8 valid fraction, printable fraction, `small_1_26`, Base64 run, octal fraction, uppercase-hex fraction, and uppercase-space fraction. `audit.json` retains every highlighted real value, negative maximum, parameters, source tier, and comparison flag.

These maxima are selected from hundreds of millions of contexts and compared with one broad-sweep negative realization. Exceeding it on scattered endpoints does not establish statistical significance or identify a plaintext. There is no repeated per-grid null distribution, familywise calibration, or predeclared threshold in these files. The corrected conclusion is a finite heuristic negative: no compelling candidate was retained in the declared grid, while the stored data do not support the stronger “at or below on every endpoint” sentence or a universal cipher exclusion.

## Lowercase comparator mismatch

The real lowercase reading uses the glyph alphabet `0123456789abcdef`. The only stored broad-sweep negative uses `0123456789ABCDEF`, and `readings.js` likewise generates only uppercase-hex null strings. Because uppercase and lowercase letters have different Base64 sextet values, this is a different decoded-byte distribution. No separate lowercase null exists in the captured source, targets, or outputs. The lowercase-vs-uppercase comparison must therefore be labeled distribution-mismatched.

## Evidence and reproduction

The package freezes `out_t0.json` through `out_t3.json`, all seven stored targets, the assembly/worker/dispatcher sources, endpoint and key helpers, both small key lists, and the exact compressed large dictionary. Every local dependency has a byte length and SHA-256 entry in `audit.json`.

```sh
cd research/rev7-20260909-codex/coverage/fable_b64_t3_completion
node controls.js
python3 -B audit.py
```

The Node command performs the exact parser and insertion-ordered `Set` union using a temporary decompressed dictionary. The Python command verifies all frozen hashes, all tier trial/error fields, the 80-context formula, the complete merge, the positive metadata, and the uppercase/lowercase target alphabets against the frozen ledger. Neither command evaluates Rev7 through a cipher.

## Limits

This completion establishes that the reported 396,081,280 finite trials exist in the four stored outputs and are internally consistent. It does not independently reproduce their cryptographic calculations, calibrate endpoint-selection probabilities, cover keys or algorithms outside the declared registry, or turn the all-hex Base64 statistical objection into a mathematical impossibility theorem.

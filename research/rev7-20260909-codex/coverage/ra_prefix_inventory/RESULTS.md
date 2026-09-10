# RA first-layer prefix inventory results

Identity: **ASTRA**.

The single preregistered run completed successfully in unified-exec session
`63647`. It evaluated the exact first-layer boundary returned by
`LayerParams::decrypt`, before XF, codec, layer 2, postprocessing, or a terminal
RA oracle. No candidate was filtered by a hit cap and every successful output
is retained byte-for-byte.

## Registered scope

The complete grid contains **16,128 labelled contexts**:

- one `hex-exact` transcription;
- raw pre-transform `identity`, `reverse`, or `reverse_words`;
- 16 baseline RA primitives;
- 7 modes;
- 6 literal key labels;
- 4 key-derivation policies;
- 2 IV labels;
- tool formatting fixed to `none`.

This is `3 * 16 * 7 * 6 * 4 * 2 = 16,128`. The gate SHA-256 is
`2b62a72c061a7cc81c0e23acdd05a6b32bc763f0426ecb79515d14777a2b9ce7`.

## Results

| Status | Total | Per raw pre-transform |
|---|---:|---:|
| successful (`ready`) | 11,700 | 3,900 |
| layer inapplicable | 4,428 | 1,476 |
| all labels | 16,128 | 5,376 |

All **11,700** successful outputs have length 546 and were scored on the full
output by the frozen exact occupancy scorer. The threshold at n=546 is
D <= 188. Results:

- flagged: **0**;
- unflagged: **11,700**;
- unsupported/untested length: **0**;
- minimum D: **210** (one labelled context);
- maximum D: **240** (two labelled contexts).

The complete distinct-count frequency distribution is:

```
210:1 211:1 212:20 213:18 214:29 215:45 216:150 217:145
218:177 219:233 220:416 221:558 222:657 223:881 224:1010
225:992 226:1085 227:1010 228:979 229:880 230:646 231:675
232:379 233:286 234:212 235:89 236:46 237:40 238:32 239:6 240:2
```

Exact byte comparison collapses the 11,700 successful labelled rows into
**7,029 unique outputs**. Sorting those byte strings lexicographically and
hashing each as `u64be(length) || bytes` gives SHA-256
`d2e7d40ee31e0cb8e87cc6e4ef7205ee69d23e2fb2ffe7d9318269f9296ec188`.
Their combined uncompressed byte length is 3,837,834. The canonical compact
JSON encoding of the saved `exact_output_groups` array has SHA-256
`1fce42a5b1d952d75e379e021e3902b22f1505f9d675a21b39d2576db87a6d31`.
Every ready row appears in exactly one saved group; no failed row appears in a
group.

## Artifacts

- `target_results.json`: 27,195,205 bytes, SHA-256
  `448ff7f95d9d07a334439ec4ddca831da5d15173bcba104858aed337f4cd67cb`.
- `target_results.json.gz`: 5,969,825 bytes, SHA-256
  `866caa935716fb84142d95c901583cd8adeacc13fd7ad5d280692c5745efd306`.

The gzip uses compression level 9, mtime 0, and an empty embedded filename.
Decompression was checked byte-for-byte against the untouched JSON and
reproduces its exact length and SHA-256.

## Finite interpretation

The result finds no output below the preregistered per-output occupancy cutoff
within this exact RA first-layer grid. It does not identify or reject outputs
with D > 188, infer English, test unsupported output lengths, or cover keys,
primitives, modes, IVs, preprocessing, transcription variants, or layer
constructions outside the registered axes. Occupancy is an iid-uniform screen,
not a mathematical cipher exclusion.

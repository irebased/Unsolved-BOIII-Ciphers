# Final saved-result review

Identity: **ASTRA**. This review evaluates the saved certificates without rerunning any cipher or target search.

## Result

The single authorized target run produced 2,700 rows and exited successfully. The frozen result is 19,018,549 bytes with SHA-256 `4f183b3f688a830fe880bccf078c1ac79dc5090a976ebd26768e18347bdfd243`.

Every row is certified below the declared 75% ASCII threshold: the permitted count is 410 of 546 bytes, while the recomputed upper bounds range from 273 to 331. All 2,700 rows are consequently also excluded from the stricter 100% ASCII endpoint by a recomputed numeric bound; no CSP-only exclusion or survivor is involved.

| Family | Rows | Minimum bound | Maximum bound | Assignment fallback | Pair fallback | Prior exact overlaps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Additional full OFB/CTR/Panama/Arcfour | 1,560 | 279 | 326 | 0 | 0 | 0 |
| Historical OFB8 recurrence | 1,140 | 273 | 331 | 10 | 0 | 40 |
| **Total** | **2,700** | **273** | **331** | **10** | **0** | **40** |

The evidence classifications contain 2,660 source-supported rows and 40 empirically supported Panama/Arcfour rows. More specifically, 1,520 additional block-mode rows are source-supported, 1,140 OFB8 rows use the pinned recurrence plus actual ECB primitives, and 40 stream rows rely on the previously declared empirical fixed-keystream probes. The 40 prior-overlap records are exact context overlaps, one retained overlap entry per cell.

The minimum 273 is attained by four OFB8 Blowfish cells recorded in the result summary. Only ten rows required the exact maximum-weight assignment bound after the row-max bound was insufficient; none required the ordered-pair fallback.

## Independent integrity replay

`verify_result.js` reconstructed all five display orientations, the exact 540-base/2,700-cell grid, every 16-by-16 high-nibble matrix, all row-max bounds, the ten assignment bounds, statuses, summaries, and source/gate pins. It bound 1,560 full keystream hashes to controls. For OFB8 it bound all 1,140 rows to exact 64-byte control prefixes, additionally bound the 180 AES/DES/Blowfish orientation rows to their 36 exact 256-byte PyCryptodome prefix references, and required full 546-byte keystream equality across all five orientations of each base context. This accurately reflects the available control lengths and does not claim a full-length independent OFB8 cryptographic replay.

The generated verification receipt has SHA-256 `e2e2cbff68db73fb0304db86785d24b5dcf6d6f33c03b4213679546f8faae70e`. A subsequent default read-only replay passed against that receipt.

## Pre-target verifier correction

Review caught a JavaScript runtime defect before target authorization: the independent assignment DP declared its changing accumulator with `const`. Syntax checking accepted the file, but executing an assignment-bound row would have thrown. The accumulator was changed to `let`, and the actual verifier function was executed on a zero matrix, a distinct-diagonal matrix, and all eight frozen reduced fixtures. Each reduced fixture matched an independent exhaustive 4-by-4 optimum and witness count. The frozen verifier-control SHA-256 is `01197d32cf2973e91def23040d3886932e987b8c139ba863ad02f58005e04022`. The final verifier SHA-256 is `51462df2cd40c065ddda378ae0f25d49e1d9dd06f36f776e37cf3a7351b186c7`.

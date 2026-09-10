# Generic lossy-four-map all-IV target results

Identity: **ASTRA**

All 48 logical contexts are complete and retain zero terminal plaintext suffixes. The run evaluated 44 new contexts exactly once and reused the four previously certified `N1310-C01`/`2013` contexts. No cell reached either registered cap.

| Map class | Evidence | Roots per orientation | Accepted states, four orientations | DES block calls, four orientations | Maximum live frontier |
|---|---|---:|---:|---:|---:|
| `N1310-C01` | reused prior | 4,096 | 114,486 | 130,870 | 60 |
| `N1310-C02` | new | 4,096 | 108,725 | 125,109 | 59 |
| `N1310-C03` | new | 4,096 | 116,070 | 132,454 | 96 |
| `N1310-C04` | new | 4,096 | 128,384 | 144,768 | 65 |
| `N1310-C05` | new | 256 | 47,563 | 48,587 | 144 |
| `N1310-C06` | new | 4,096 | 117,457 | 133,841 | 72 |
| `N1310-C07` | new | 256 | 50,073 | 51,097 | 190 |
| `N1310-C08` | new | 256 | 45,921 | 46,945 | 142 |
| `N1310-C09` | new | 256 | 48,348 | 49,372 | 143 |
| `N1310-C10` | new | 4,096 | 135,433 | 151,817 | 71 |
| `N1310-C11` | new | 256 | 48,857 | 49,881 | 128 |
| `N1310-C12` | new | 256 | 68,581 | 69,605 | 223 |

The 44 new contexts account for 915,412 accepted states and 1,003,476 DES block calls. The four reused contexts account for 114,486 accepted states and 130,870 calls. The logical totals are 1,029,898 accepted states and 1,134,346 calls. Reused evidence is reported separately and was not recomputed during the authorized target run.

## Independent verification

`verify_results.py` binds the frozen gate, source package, inventory, canonical MDX/dataset, exact ordered Cartesian grid, and prior result/certificate. For the 44 new cells, it independently reconstructs every representative key's source emission map, enumerates ciphertext bytes before applying the printable-plaintext predicate, and advances every compatible initial register until its frontier is empty. This second negative-prefix computation reproduces every accepted-state array, block-call count, maximum live frontier, and initial-register digest.

For the four reused cells, it verifies the complete `N1310-C01` emission map is identical to `2013`, checks the prior zero certificate, and compares every copied search field with the pinned prior result. These cells are not counted among the 44 independent new replays.

The certificate ledger records all 44 empty-prefix histograms, latest-reaching roots, and root-outcome digests. It verifies 4,096 roots for each dropped-column-1 cell and 256 for each dropped-column-3 cell.

## Finite scope

The result covers DES CFB8 with key `Zombies\0`, 655 natural ciphertext bytes, the 12 finalized source-map classes, four canonical orientations, every observation-compatible `C[0:8]` register, and printable ASCII plaintext bytes `0x20..0x7E` from offset 8. It does not recover or constrain the original IV-dependent first eight plaintext bytes, score language, or cover other ciphers or source maps.

## Verification command

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy4_alliv_controls/target/verify_results.py
```

## Hashes

- Gate: `816ea9f8dc83414147e01e6a11983769e48ede21649e21262f07defa8f7ab55c`
- Full result: `25286408d594956aab904e3e4111866160c300b85a8eb73c61791285733dd507`
- Independent verifier: `470c30e78ea6decad821becb4e84b7b58f389b5b1f8e344c860dbd1f7cfe18b3`
- Independent certificate ledger: `aaaff0103358d89ea55df467a64364968e43b3fd676cf07255f42c5955fd04f5`

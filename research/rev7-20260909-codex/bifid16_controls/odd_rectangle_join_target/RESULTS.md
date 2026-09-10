# ASTRA odd typed-rectangle join result

The single authorized run evaluated the exact 80 cells left unresolved by the accepted odd single-typed-graph filter. All 80 are exhaustive `unsat`; none are `sat` and none reached either registered cap. There are therefore no residual IDs or coordinate witnesses in this 80-cell follow-up.

The join enumerated 5,329 candidate pairs in total. The maximum per-cell join space and examined count was 703 at `reverse:p365`. The largest RC candidate count was 112 at `reverse:p383`; the largest CR candidate count was 35 at `byte_reverse:p367`. All candidate spaces were exhausted. The obstruction totals were 5,165 geometry failures and 164 RR-edge failures; no other obstruction was needed.

Together with the parent result's 2,104 single-graph exclusions, this closes its exact 2,184-cell grid: four canonical orientations and every odd period from 1 through 1091 for two arbitrary fixed 4x4 Bifid squares under the bag213 high-nibble necessary condition. This is a finite coordinate-avoidance exclusion. It is not a full UTF-8 or plaintext decoder, does not cover changing squares, non-4x4 alphabets, altered Bifid rules, or transformations outside the registered orientations.

The result was produced once with preprocessing candidate cap 10,000 per typed list and join cap 1,000,000 per cell. Neither cap was reached. `--verify` reconstructed the canonical orientations and source indices through the accepted parent driver, checked every saved graph, replayed every exact join, and validated the aggregate accounting. This verification repeats the controlled join implementation; it is not a second independent target search.

## Reproduction and evidence

Authorized target command:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/run_target.py --run-target
```

Read-only verification command:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/run_target.py --verify
```

- Driver SHA-256: `0520c0f710b281735e594f29a3375c922ad4eb5acba7aa83d7872ea4832b3d8d`
- Authorization gate SHA-256: `0ab98eb9ce6f8e5018a515aeec4e3db1a0a1aa67ebf405e7ba599ddd504b2151`
- Join model SHA-256: `221ea25d48f80a26476e1fe4abea0e89e099bf35f4325ed8e8f7aef6bd00be45`
- Selection ledger SHA-256: `c303e6fa80a8346b1868e202bc3f3e8dcf309ca5fcfa204cc77c9b00aaf8f085`
- Driver-control ledger SHA-256: `4a0709c485bcfba792800d8032bc4efc7794b8fb37533ff4da8218742b6fea4a`
- Parent result SHA-256: `1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d`
- Parent verification receipt SHA-256: `5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952`
- Result SHA-256: `46fe703714c05abf9fe32127f9e1517a1e8a6db8b4184b4825130611e66b6df4` (104,748 bytes)
- Verification receipt SHA-256: `3facf405ef174105bec0b51438f74532b5fc603a15260e335349f4a677ba3ff8` (263 bytes)
- Recorded target elapsed time: 1.454586744 seconds

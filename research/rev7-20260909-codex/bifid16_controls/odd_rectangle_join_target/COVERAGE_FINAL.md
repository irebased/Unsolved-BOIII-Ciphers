# ASTRA final fixed-square Bifid coverage ledger

The saved evidence now excludes all **4,368 registered cells** for direct decryption through one standard 4x4 Bifid layer with an arbitrary fixed cipher square and an arbitrary fixed plaintext square. The grid is the four canonical orientations of the 1,092 displayed hex symbols and periods 1 through 1,092. It includes the same-square case as a subset of the two-fixed-square model.

The necessary endpoint is `bag213` = `{09,0A,0D} ∪ {20..7E} ∪ {80..BF} ∪ {C2..F4}`, containing 213 byte values. Because it contains no byte whose high output nibble label is `1`, every admissible decoded byte must avoid that **output nibble label**. For an arbitrary plaintext/output square, the forbidden coordinate is `Sp(1)` and varies with the square; it is not the fixed numeric coordinate 1. The exclusions prove that no fixed pair of 4x4 squares can avoid its corresponding `Sp(1)` in any registered cell.

## Evidence partition

- All 2,184 even-period cells are excluded for every ordered pair of fixed cipher/plain squares by `even_rectangle_target/broad_reconciliation.json` (`a5dbf6d4dd79769daf7756160f7f3d861c2aa3dfdebc6dfc1514aae238434295`).
- Of the 2,184 odd-period cells, the accepted single-typed-graph result excludes 2,104 and identifies an exact ordered complement of 80.
- The joint typed-rectangle run exhausts all candidates in those 80 complement cells and returns 80 UNSAT, 0 SAT, and 0 incomplete. Its result SHA-256 is `46fe703714c05abf9fe32127f9e1517a1e8a6db8b4184b4825130611e66b6df4`.
- The independent replay uses a different RC/CR candidate construction and direct bitmask joins. It reconstructs every candidate list and all 5,329 obstruction records without importing the production join model. Its ledger SHA-256 is `4e4c7c74f61e04c1152c1887867b6cb70145122b9624a0bf8e51366c8d7824fa`.

The independent replay forms each RC or CR candidate by choosing the unique shared symbol first and then choosing three symbols outside the first class. It sorts these pairs lexicographically, joins RC and CR candidates using only set/bitmask relations, and recomputes the production record indices, obstruction reasons, and SHA-256 trace. It reproduces 5,165 geometry obstructions, 164 RR-edge obstructions, and no CC-edge obstruction.

Run the read-only independent replay and combined partition reconciliation with:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/independent_replay.py
python3 -B research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/reconcile_two_squares.py
```

## Scope limits

This covers the registered **direct layer and decrypt direction** only. It assumes the standard 4x4 Bifid coordinate transpose with two squares that each remain fixed for the whole message. The four input orientations are: `forward = s`; `reverse = s[::-1]` over all 1,092 symbols; `byte_reverse` reverses the 546 two-symbol byte pairs while preserving each pair; and `nibble_swap` reverses the two symbols within every pair. The older even ledger calls the same `s[::-1]` operation `full_hex_reverse`; the pinned drivers implement the two labels identically. Period 1,092 represents the whole block; larger nominal periods have the same single-block geometry for this 1,092-symbol input.

The bag213 condition contains every byte that can occur in well-formed UTF-8 scalar text when ASCII is restricted to TAB, LF, CR, and printable characters. Byte membership alone is weaker than that complete UTF-8 grammar. The exclusion is valid for this declared endpoint but does not reconstruct plaintext; UTF-16, arbitrary binary, and text requiring other ASCII controls are outside its scope. The ledger does not cover changing squares, non-4x4 alphabets, encryption direction, another intermediate layer, insertion/deletion or transcription repair, unregistered transforms, or arbitrary classical-cipher families. It is not a whole-cipher closure and does not assert that the overall Rev7 problem is solved.

## Immutable artifacts

- Independent source SHA-256: `4d86b9414843bfbeca0136250696e9aca454ab6e1ab76f4095be6641064775bc`
- Independent ledger SHA-256: `4e4c7c74f61e04c1152c1887867b6cb70145122b9624a0bf8e51366c8d7824fa`
- Combined reconciliation source SHA-256: `079dc54eabbd86dc43b94a8caaf5638f33f72327e83235332195dc2f4a481910`
- Combined reconciliation ledger SHA-256: `4618295aca0e67294851f097a1c68010e4f109639242163447ba5b16a3407bae`
- Joint target result SHA-256: `46fe703714c05abf9fe32127f9e1517a1e8a6db8b4184b4825130611e66b6df4`
- Joint verification receipt SHA-256: `3facf405ef174105bec0b51438f74532b5fc603a15260e335349f4a677ba3ff8`
- Parent odd result SHA-256: `1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d`
- Parent odd verification receipt SHA-256: `5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952`

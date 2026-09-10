# One visible-token group reversal G — target-free preparation

Identity: ASTRA. This package adds one orientation only. Natural hexadecimal ciphertext is split from the left into width-5 tokens and the token order is reversed without changing token interiors. At length 1092 the final natural token has length 2, so observed text begins with that two-symbol token. Inversion therefore first takes the leading two symbols, then width-5 observed tokens, reverses the token list, and joins it; ordinary left regrouping is not an involution here. The natural token lengths are `[5]*218+[2]`; the observed token lengths are `[2]+[5]*218`. The controls compare token slicing with an independent closed-form index permutation.

`controls.py` uses synthetic 546-byte text and two distinct fixed random 4x4 squares. It checks index permutations and inverse geometry (including truncated final groups), distinguishes G from the four previously tested orientations, and round-trips Bifid periods crossing both Bifid and width-5 boundaries. Representative even and odd cases traverse the same necessary-proof dispatcher and are never excluded, as a planted valid square requires. A capped odd join is recorded as incomplete.

The inert driver registers periods 1..1092 for this single G. Even-block cells use the accepted pair-cardinality bound followed by the empty-rectangle condition. Odd-block cells use the accepted single typed-graph filters and coupled join. A coupled-join cap yields `incomplete`, never exclusion. SAT means unresolved. Period 1092 represents the one-full-block behavior for all p>=1092; those larger labels are not added.

No canonical ciphertext is read by the default command or controls. Canonical extraction is reachable only through `--run-target`, requires a root-created `target_gate.json`, and refuses existing result, temporary, or checkpoint files. No gate or target result is included at this stage.

Commands from the repository root:

```sh
python3 -B research/rev7-20260909-codex/bifid16_controls/group_reverse_extension/controls.py
python3 -B research/rev7-20260909-codex/bifid16_controls/group_reverse_extension/run_target.py
```

Scope limits: the necessary conditions cover two arbitrary fixed 4x4 squares (cipher-coordinate and plaintext-inverse squares may differ); the conventional one-square family is included. The new controls retain a one-square geometry fixture and twelve distinct-square end-to-end plants. An independent labelled-coordinate construction checks every typed graph and source-position tuple, and independently derives the even pair streams. The concrete input-square mapping and output-square location of label 1 satisfy the missing-coordinate witness in every planted period. The direction is standard Bifid decryption, with two output nibbles forming each byte. Its exact bag213 is TAB/LF/CR, bytes 32..126, 128..191, and 194..244. The even rectangle and odd coordinate tests use both its cardinality and its absence of high nibble 1. Bifid encryption direction, other group widths, character encodings, binary layers, and compositions with global reversal remain outside this package.

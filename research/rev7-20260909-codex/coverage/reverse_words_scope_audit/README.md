# ASTRA audit of word reversal in the sweep path

Identity: ASTRA.

The captured `ra` sweep removes ASCII whitespace before applying `--pre`. Consequently `reverse_words` sees one token on Rev7 and duplicates identity. The separate `ra run` path preserving raw whitespace does not validate sweep behavior. The claim verification/recompute path repeats the same compact-input wiring.

All four relevant Rust files and all 25 stored claim files are captured from commit `e6c282187cc8a555580349d819210b544e5417b1`. Default replay checks exact SHA-256 values, every source excerpt against the full captured file, and the zero literal axis-term counts in the captured claims. These counts establish a bounded inventory, not absence of private runs.

```sh
python3 -B research/rev7-20260909-codex/coverage/reverse_words_scope_audit/audit.py
```

Python 3 and Rust are required. The only compiled code is a tiny target-free ASCII-whitespace fixture. Synthetic token reversal is evaluated independently in Python; no Rev7 cipher is tested. The six selected earlier ASTRA files are hash-pinned as dependencies. Source captures are immutable; this audit does not edit or execute the shared RA checkout.

The leading two-character group is conditional evidence only: given prior left-to-right grouping, both character reversal and whole-token reversal move a final short group to the front. The layout alone proves neither that reversal happened nor which reversal was used.

A genuine token-order transformation is outside the four explicitly named orientations in the published Bifid result. Their proofs remain valid. The proposed new G input needs new position-dependent certificates because five-character groups cross byte boundaries. That separate experiment is prepared in `bifid16_controls/group_reverse_extension`; it is not run by this audit.

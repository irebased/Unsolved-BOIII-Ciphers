# Synthetic control report

Identity: **ASTRA**. Target evaluated: **false**.

The indexed gather, complete RFC 3629 DFA, fixed CFB8 backend adapters, source pinning, and streaming accounting passed all registered controls. The committed `controls.json` is 384,884 bytes with SHA-256 `5237b660e4f72ff42f31c7872777cc4c29d7ad42f3d0ce959479cd44a3396f1a`.

Key evidence:

- 65,792 length-1..2 strings and 29,184 bounded length-3..5 byte-class cases agreed with independent strict-decoder oracles.
- All 1,112,064 Unicode scalar values encoded and reached the boundary state.
- 48 geometry cases covered widths 2..9, both starts, and multiple orders; 17,472 recovered byte pairs crossed observed-column boundaries.
- All 80 valid crypto plants, spanning ten backends, four orientations, and two IVs, retained exactly one intended backend suffix. Across 800 evaluated contexts, the other 720 were rejected.
- Ten malformed plants recorded an exact first byte/state/reason witness. A separate trailing-lead fixture produced a terminal rejection at the true end.
- The exact 20,000-order benchmark evaluated 200,000 contexts in 2.0351 seconds on the recorded host, with 693,698 block callbacks and no retained random contexts. Linear projection to the proposed 1,636,448-order scope was 166.5 seconds; this is synthetic-input and host-specific.

The filter establishes only RFC 3629 validity of the known CFB8 suffix for valid permutation geometry. It does not establish English plaintext, recover an IV, cover repeated-label lossy AMSCO behavior, or reproduce PHP character handling. No Rev7 ciphertext or target search was read or run.

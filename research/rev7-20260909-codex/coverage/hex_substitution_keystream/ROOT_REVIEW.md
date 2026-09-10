# Root review of the fixed-keystream bound

Identity: ASTRA.

For ASCII TAB/LF/CR/32..126, the high nibble is in {0,2,3,4,5,6,7}. For an inverse hex map g and fixed stream K, the high plaintext nibble at byte i is g(display[2i]) XOR (K[i] >> 4). XOR has no carry from the low nibble. Therefore, for each high displayed symbol a and possible image v, counting compatible positions yields W[a,v]. Any mapping has at most sum_a W[a,g(a)] allowed bytes, bounded by sum_a max_v W[a,v]. This bound holds even if g is not injective; it deliberately ignores low-nibble restrictions.

At length 546, at least 75% requires at least 410 allowed bytes. A bound of 409 or lower is conclusive for the stated model. A bound above it is unresolved unless a tighter valid bound decides the threshold. The full-ASCII solver cannot exclude a 75%-ASCII candidate merely by returning unsatisfiable.

Root read model.js and controls.js, checked the proof and threshold handling, and ran the unchanged default control check:

```sh
node research/rev7-20260909-codex/coverage/hex_substitution_keystream/controls.js
```

Actual result: PASS, 156 qualifying contexts, 30 shuffled-map plants, exit 0 (tool chunk 09f290). Control ledger SHA256 a1446e169e077446ab638c56d2c52de6f52402b116c3238add3079d68a592037. Four reduced-symbol brute-force fixtures bound all assignments to four observed symbols. Separately, root executed the independent bound_reference.py control suite: 64 reduced-alphabet exhaustive cases PASS, exit 0 (e28e44).

The source-level OFB/CTR proof covers the captured wrapper's mode recurrence. Panama/Arcfour underlying C modules are absent from the frozen capture; their XOR independence is supported by behavioral probes, so the 20 orientation-labelled stream cells retain that empirical limitation. The 760 block-mode cells and 20 stream-model cells must be reported separately. Enigma and WAKE are excluded after concrete XOR-law failures.

No target data was evaluated during this review. The forthcoming target is a bounded 780-cell certificate calculation, not a literal enumeration of 780 times 16! decryptions.

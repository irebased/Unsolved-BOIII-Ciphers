# Fixed-keystream global-hex-map CSP controls

Identity: ASTRA. This directory is synthetic-only and does not read or evaluate
Rev7. It covers two fixed-keystream modes: historical libmcrypt OFB8 and
standard full-block OFB. Ciphers are AES128, raw-seven-byte Blowfish, and DES
with the registered `Zombies` keys. IVs are ASCII zero, NUL, and the block-size
prefix of SHA-1 over raw `Zombies`. CTR is deliberately outside this scope.

For each displayed hex pair at position `i`, the solver constructs the
necessary relation

```text
(16 * map[high] + map[low]) XOR keystream[i] in RELAXED
```

and intersects that relation across every occurrence of the same ordered
display pair. `RELAXED` is printable ASCII, TAB/LF/CR, plus the six individual
bytes used by UTF-8 `E2 80 93/94/98/99`. Complete relation survivors are then
replayed in original byte order through the stateful endpoint FSA; the final
state must be zero.

The solver enforces a 16-variable all-different map with MRV and iterative
support filtering. A value is removed only when no relation-compatible partner
remains or it is consumed by all-different. An empty domain therefore proves
that no completion exists. For the factorial certificate, every unused value
is still enumerated for the selected variable. Each support-pruned assignment
charges exactly `(16-assigned)!` completions. Those branches are disjoint;
with terminals they sum to `16!` for an uncapped root traversal.

Reproduce:

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/stream_csp
python3 -B controls.py
```

The script refuses to overwrite `controls.json`. The frozen controls verify:

- all 12 actual libmcrypt C-harness OFB8 fixtures;
- full-block OFB against PyCryptodome for all three ciphers and three IVs;
- six unseeded 546-byte, full-16-symbol planted-map searches containing all four
  allowed UTF-8 punctuation sequences;
- independent direct-XOR naive enumeration of all 24 four-unknown mappings for
  each cipher and both modes;
- repeated pair intersections and same-symbol nibble pairs; and
- a relaxed `E2 80` suffix that the final FSA correctly rejects as truncated.

All six full-map plants completed in 17 accepted CSP nodes, certified all
`16!` mappings, recovered the unique planted mapping, and produced one
relaxed and one FSA-valid survivor.

Additional root-pruning controls prove an empty repeated-pair relation across all 16 diagonal assignments, a conflict between two independently nonempty relations that both force value 5 across all 240 distinct assignments, and a one-node cap with zero terminals and an explicitly incomplete certificate.

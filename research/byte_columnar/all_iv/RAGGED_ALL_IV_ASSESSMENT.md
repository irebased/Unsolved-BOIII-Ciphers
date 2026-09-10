# Ragged variant-B all-IV assessment

Identity: ASTRA. This is a proof and scope assessment only; no additional target data was evaluated.

Let `n=q*w+r`, where `q=floor(n/w)` and `0<=r<w`. In FABLE variant B, the pre-transposition ciphertext is stored as natural-column chunks. The observed stream is emitted row-major, visiting natural columns in `order` and skipping invalid cells in the ragged final row.

The first `q` observed rows are complete for every column, regardless of the `first` or `last` long-column convention. Therefore, for observed rank `j`,

```
observed[j : q*w : w]
```

is exactly the first `q` contiguous ciphertext bytes of whichever natural column is assigned to rank `j`. This statement is independent of which observed ranks receive the `r` long natural columns. The compressed ragged tail begins at `q*w` and must be ignored by this predicate.

Using `observed[j::w]` is incorrect when `r>0`: Python's stride can select a byte from the compressed tail whose tail position no longer equals the full-row observed rank because short columns were skipped. The rectangular helper is therefore not reusable unchanged.

## Strong contradiction

For CFB8 with block size `B`, bytes `B..` within any contiguous ciphertext chunk decrypt independently of the external IV and of ciphertext preceding that chunk. Start the endpoint automaton at chunk-relative byte `B` with the relaxed reachable state set `{0,1,2}`. If the guaranteed suffix `observed[j+B*w : q*w : w]` empties that set, observed rank `j` is an unavoidable invalid chunk.

Every complete variant-B column order assigns every observed rank to exactly one natural column. Consequently, one invalid observed-rank chunk excludes every order. Because the predicate ignores the tail, the same witness applies to both FABLE `first` and `last` conventions and to every order-induced allocation of their long natural columns to observed ranks. For each convention the certificate is the complete `w!` order space. The two convention statements should be reported as parallel model exclusions, not added as independent factorial weight.

A clean set of rank chunks remains unresolved. The predicate does not recover the order, the IV, the tail assignment, or plaintext bytes before the self-synchronization boundary.

## Exact AES range at n=546

AES has `B=16`. For the scoped column widths `w>=2`, a nonempty guaranteed suffix requires `q>16`:

```
floor(546/w) >= 17  iff  2 <= w <= 32.
```

Width 32 has `q=17` and only one IV-independent test byte per rank. Width 33 has `q=16` and provides no guaranteed suffix, so this proof yields no evidence there. The useful finite structural scope is therefore widths 2–32, variant B, four canonical orientations: `31*4=124` symbolic all-IV cells. Both ragged conventions are covered inside each cell by the same tail-free witness.

The completed rectangular widths 13 and 14 account for eight of those cells already. A future extension can replay them as a source-prefix check, but should report 116 newly evaluated width/orientation cells rather than claim 124 new exclusions.

The work per cell is small: at most 32 ranks, each with at most `q-16` AES recurrence bytes. At width 32 each rank supplies only one necessary byte test. Retaining one rank does not recover a chunk; the entire cell remains unresolved only if every rank is retained.

## Controls required before registration

1. Match FABLE's exact ragged variant-B inverse on fixed `r>0` fixtures for both `first` and `last`.
2. On valid arbitrary-IV plants at exact and ragged widths, show that every guaranteed rank prefix is retained.
3. Corrupt one guaranteed full-row ciphertext byte at relative offset 16 to force plaintext byte zero; show that the bad rank rejects while the other valid ranks retain.
4. For small widths, enumerate every order under two IVs and both conventions and confirm that one bad unavoidable chunk eliminates all full valid plaintexts.
5. Mutate every ragged-tail byte without changing the predicate result, proving that the implementation does not accidentally consume the compressed tail.
6. Give width 32 a positive and negative one-byte suffix control, and assert that width 33 is unsupported because `q==16`.
7. Store the exact rank slice, full guaranteed ciphertext prefix, IV-independent suffix, and first FSA failure for every rejection.

The target, if later authorized, should remain AES with fixed `Zombies`+9NUL key, CFB8, external-IV framing, variant B, and the registered five-sequence endpoint. This structural extension does not justify adding modes, keys, or ciphers.

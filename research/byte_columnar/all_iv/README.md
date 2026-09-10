# ASTRA all-IV first-column controls

This directory contains synthetic controls only. It does not read or evaluate Rev7 and has no target driver.

The predicate addresses one narrow model: rectangular FABLE variant B at byte widths 13 and 14, AES-128 CFB8 with fixed key `Zombies` followed by nine NUL bytes, and an arbitrary external 16-byte IV.

For a proposed observed rank `j` of natural column zero, variant B exposes the initial reconstructed ciphertext chunk as `observed[j::width]`: 42 bytes at width 13 and 39 bytes at width 14. In CFB8, after ciphertext byte 15 the register contains only ciphertext, so plaintext bytes from offset 16 onward are independent of the external IV. `core.py` computes those bytes directly from `AES_ECB(ciphertext[i-16:i])[0] XOR ciphertext[i]`.

The skipped 16 plaintext bytes could leave the strict endpoint FSA in state 0, 1, or 2. The predicate therefore propagates the full reachable state set `{0,1,2}` across the exposed suffix. It rejects the rank only if that set becomes empty. It deliberately does not require terminal state zero at the column boundary because later columns follow.

A rejected rank eliminates `(width-1)!` full column orders for every external IV. If all `width` ranks reject, the disjoint weight is `width!` and the model has a complete every-IV contradiction for that width/observed stream. A retained rank is only an unresolved first-column class. It is not a recovered IV, plaintext, or full permutation.

## Controls

- Two PyCryptodome CFB8 decryptions of one 42-byte ciphertext under different IVs have different prefixes but identical suffixes from byte 16; both match the direct ciphertext-only recurrence.
- Boundary fixtures place `80` and `93` at suffix offset zero. Starting only in state zero wrongly rejects them, while propagating `{0,1,2}` retains the valid continuation. Truncated UTF-8 is still controlled by later complete validation, outside this necessary-prefix predicate.
- The fixed width-3 variant-B inverse fixture matches FABLE's pure `byteTranspositions.js` result exactly.
- At widths 3–6, independent naive enumeration decrypts every complete permutation under the known plant IV. Every first-column rank supporting a fully valid plaintext is contained in the necessary predicate's retained set.
- Deterministic 546-byte plants contain all five admitted punctuation sequences and use a nontrivial column order plus an arbitrary IV. Their correct first-column ranks are retained at widths 13 and 14.
- For a deterministic random 546-byte observed stream, every rank rejects at both widths, producing exact `13!` and `14!` synthetic contradiction certificates.

All ranks are retained in the valid 546-byte plants. This is expected: each true natural-column chunk is a contiguous segment of a valid plaintext after self-synchronization, so the necessary predicate cannot identify which valid chunk belongs first. The test is designed as a fast contradiction, not an order-recovery search.

Run from `/private/tmp/rev7-astra-20260909` in a fresh copy without `controls.json`:

```sh
python3 -B research/byte_columnar/all_iv/controls.py
```

The source refuses to overwrite the frozen ledger.

Hashes:

- `core.py`: `9a8fb8cd37ecd2453eb191c340d3da14c1a95565d7b2582d76bf4ccaa7c8f16e`
- `controls.py`: `360ef4132575a3db3107128d709bb2403be0f9cb625f7a9c77000af8aa281a89`
- `controls.json`: `991ded8a5e798a51805de9896ae2af054cad610a62a553dff2b8548ad1185825`
- FABLE `transpositions.js`: `89f2b3c8fa5cd5144d3c2baf2e2d25edb1dcb2f3b0f7a056a506841e6438ccc6`
- FABLE `byteTranspositions.js`: `c9c09bd405bbe43b853a5efb0e25f58ae67136a5f83653e7c45c3a2f3879b7f0`

Identity: ASTRA.

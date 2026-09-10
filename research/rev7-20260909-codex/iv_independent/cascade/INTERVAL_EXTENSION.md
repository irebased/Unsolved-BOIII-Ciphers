# Known-interval CFB8 cascade extension

**Identity:** ASTRA. Synthetic controls only. Target evaluated: **false**; Rev7 is not read.

The direct cascade proof exposes a suffix because every CFB8 layer discards an IV-dependent prefix. An interlayer reversal moves that known region, so this extension tracks an absolute interval `[L,R)` and its bytes.

- A CFB8 layer of block size `b` maps `[L,R)` to `[min(L+b,R),R)`.
- Byte reversal maps it to `[N-R,N-L)` and reverses its bytes.
- Nibble swap preserves the interval and swaps each byte's nibbles.
- Full hexadecimal-symbol reversal combines byte reversal with nibble swap.

The controls cover two- and three-layer mixed 8/16-byte chains. Four two-layer recipes cover each transform once. Sixteen three-layer recipes cover every ordered pair of transforms, which detects applying the right transform at the wrong boundary. Lengths below, exactly at, and above the usable boundary verify that an absent or empty interval is inconclusive. Nonempty intervals are compared with independent full PyCryptodome `MODE_CFB, segment_size=8` chains under two IV suites.

Every vector also fixes one outer ciphertext and decrypts it under two different complete IV suites. The full outputs differ outside the predicted interval, while the interval bytes are identical to each other and to the IV-free calculation. This does not claim recovery of any outside byte.

Endpoint controls use initial FSA state `{0}` only when `L=0`, otherwise `{0,1,2}`. They require terminal state `{0}` only when `R=N`, otherwise any partial state `{0,1,2}` may continue beyond the interval. Plants split `E2 80 A6` after `E2` and after `E2 80` at both exposed edges where the geometry permits. At the right edge, one byte outside leaves ending state 2 and two bytes outside leave ending state 1; the ledger records both the outside-byte count and actual expected state. Empty intervals are labeled inconclusive and never counted as rejection.

Read-only verification:

```text
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/interval_extension.py
```

Explicit regeneration to a new path:

```text
python3 -B research/rev7-20260909-codex/iv_independent/cascade/interval_extension.py --regenerate /tmp/cascade-interval-controls.json
```

The proof covers only same-length aligned binary layers and the four declared involutions. It does not cover encodings, transpositions, framing, truncation, padding changes, or other transforms.

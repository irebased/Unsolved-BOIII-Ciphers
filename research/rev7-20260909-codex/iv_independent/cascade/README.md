# Direct-binary CFB8 cascade IV-forgetting theorem

**Identity:** ASTRA. Synthetic controls only. Target evaluated: **false**; Rev7 is neither read nor evaluated.

For one CFB8 decryption layer with block size `b`, byte `i >= b` satisfies

```text
P[i] = C[i] XOR E_key(C[i-b:i])[0].
```

At that point the feedback register contains only the preceding `b` ciphertext bytes, so the external IV is absent. For direct same-length binary layers listed in outer-to-inner decryption order, induction adds the block sizes. If earlier layers expose their output from offset `B`, the next layer can compute output byte `i` once its input window `i-b:i` lies inside that known suffix, which first occurs at `i = B+b`. Therefore a depth-`d` chain exposes the final plaintext suffix from offset `sum(b_j)`.

The controls use PyCryptodome AES-128, DES, standard Blowfish, and ARC2 in five two/three-layer combinations with mixed 8- and 16-byte blocks. Every vector is independently encrypted and decrypted with `MODE_CFB, segment_size=8`, then reconstructed by the ECB sliding-window recurrence without IVs. Two distinct IV suites cover every vector. Each chain includes lengths one byte below, exactly at, one byte above, and seventeen bytes above its boundary; a sample containing every byte value; strict text containing all five registered UTF-8 punctuation sequences; and boundaries beginning in UTF-8 continuation states 1 and 2. No intermediate output is filtered for printability.

The default verification is deterministic and read-only:

```text
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/proof.py
```

Explicit regeneration writes only a new path and refuses an existing path:

```text
python3 -B research/rev7-20260909-codex/iv_independent/cascade/proof.py --regenerate /tmp/cascade-controls.json
```

The model requires direct binary layers with unchanged length and alignment, fixed known keys, and ordinary CFB8. It does not cover an encoding, reversal, transposition, framing, truncation, or padding boundary inserted between layers. It recovers no byte before the sum-of-block-sizes boundary. Historical compatibility primitives not represented by standard PyCryptodome algorithms need separate controls.

CFB mode and its feedback recurrence are specified in NIST SP 800-38A section 6.3: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

The retained local record contains completed one-layer IV-independent and raw-IV-prefix proofs, but no completed proof/control ledger for this direct-binary two/three-layer cascade before this package.

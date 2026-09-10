# Raw IV-prefix transfer for all-IV CFB8 chunk certificates

Identity: **ASTRA**. This is a synthetic proof and control artifact. It does not read or evaluate Rev7.

Let a 546-byte decoded stream be the complete raw frame `S = IV || C`, where the IV is exactly one cipher block of `b` raw bytes and the remaining `546-b` bytes are CFB8 ciphertext. For every frame index `i >= b`:

```
P[i-b] = S[i] XOR E_key(S[i-b:i])[0]
```

If a whole-frame variant-B column transform produces a natural contiguous chunk beginning at frame offset `a`, decrypting that chunk locally from relative byte `i >= b` yields:

```
chunk_plain[i-b] = P[a+i-b]
```

Thus the IV-independent chunk suffix is an exact contiguous slice of the payload plaintext, beginning at payload offset `a`. The raw IV bytes themselves are never subjected to the plaintext endpoint.

A valid payload makes every such slice valid from at least one endpoint boundary state. Therefore, an unavoidable chunk suffix that rejects from all boundary states excludes the raw-IV-prefix interpretation for every possible IV value. Existing whole-frame unavoidable-chunk certificates transfer without rerunning the target, provided the mapping or column transform acts on the entire `IV || ciphertext` frame.

Each full-frame vector also evaluates the recurrence directly at every frame index from the first payload byte through the end, asserts that the entire derived suffix equals the strict payload, and records the all-IV, mixed IV/ciphertext, and first fully-ciphertext register boundaries. Synthetic controls cover AES-128, DES, standard Blowfish, and historical Blowfish-compat CFB8; two arbitrary IVs per cipher; first-long and last-long ragged conventions; regular and q=b+1 boundary widths; exact chunk-suffix-to-payload indexing; and chunk starts inside UTF-8 punctuation. Widths with q=b are marked unsupported.

The proof does not cover ASCII or hex-encoded IV fields, an IV outside the transformed region, extra header bytes, trailing framing, transforms applied only to the ciphertext portion, other feedback modes, or other segment sizes. A retained necessary chunk does not recover an IV or plaintext.

Reproduce the synthetic ledger once in a clean output directory:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/iv_independent/raw_iv_prefix/proof.py
```

The script refuses to overwrite `results.json`.

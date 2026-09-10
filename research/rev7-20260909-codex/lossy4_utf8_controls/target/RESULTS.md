# Exact Unicode lossy-map all-IV results

Identity: **ASTRA**.

The preregistered 48-cell scan completed once. All 48 cells were exhaustive within the registered limits; none hit the 100,000-live-path or 5,000,000-accepted-state cap. No terminal plaintext suffix survived the exact 201-codepoint endpoint.

## Result

- Grid: 12 frozen CrypTool source-map classes × 4 canonical orientations.
- Cipher: DES-CFB8, key `Zombies\0`.
- IV model: every observation-compatible eight-byte initial ciphertext register, covering every external IV for plaintext bytes 8 through 654.
- Compatible roots exhausted: 104,448.
- Accepted frontier states: 4,718,844.
- DES block calls: 4,823,292.
- Complete contexts: 48; incomplete contexts: 0.
- Terminal solutions: 0.
- Earliest independently replayed empty-root position: ciphertext byte 8.
- Latest independently replayed empty-root position: ciphertext byte 276. Every root failed before the terminal byte.

`target_results.json` is 450,654 bytes with SHA-256 `c409b9ae4aafb3093694f615075f180d828ef6ec994f3719bcf612c84d44f690`. The frozen gate SHA-256 is `c5908da398b3929adc218ebb5da8b79a44b5caedc4b46067f8ded003087d9c8f`.

## Independent saved-result certificate

`verify_results.py` imports neither the target driver nor the frozen frontier core. It independently reconstructs the twelve source maps, orientations, masked ciphertext bytes, all 104,448 compatible initial registers, and a literal-codeword trie for the Unicode prefix-state transition. It enumerates observation-compatible ciphertext bytes first and derives plaintext bytes afterward. It replays the ciphertext-first necessary frontier and matches every saved per-byte accepted count, block-call count, maximum live frontier, and zero-terminal conclusion. This is an independent replay of the zero certificate; it does not represent a second search under another cipher or endpoint model.

Run from the worktree root:

```sh
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/target/verify_results.py
```

## Finite limits

The conclusion covers only the registered DES key, source-derived 12-map family, four orientations, arbitrary external IVs through the known CFB8 suffix theorem, and the exact 201-codepoint language. The first eight plaintext bytes remain unknown. A different cipher, key, source mapping, transform, encoding, or language is outside this result.

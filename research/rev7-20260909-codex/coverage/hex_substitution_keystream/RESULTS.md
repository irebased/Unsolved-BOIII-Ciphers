# Arbitrary hex substitution before a fixed keystream: results

Identity: ASTRA. Rev7 remains unsolved.

The registered 780-context experiment completed once, with no survivor or unresolved context at the 75% ASCII threshold. All high-nibble bounds were between 283 and 324 allowed bytes out of 546; the threshold was 410. Thus even the largest bound is 86 bytes below the required count. No pair relaxation or CSP fallback was needed. These are algebraic bounds over all 16! bijections, not a count of brute-force decryptions. The high-nibble relaxation also permits non-injective fixed maps and arbitrary low nibbles, so the bound is stronger than the bijective model it was designed to screen.

The conclusion covers 760 source-supported block-mode contexts and 20 empirically supported Panama/Arcfour stream-model contexts, with the conditional eligibility limitation stated in README.md. It does not identify the cipher family, key, or layer count. The global statement does not extend to unknown keys or IVs, feedback modes, arbitrary byte substitutions, or additional intervening transforms.

Forty rows overlap prior strict-endpoint OFB work by exact keystream hash and orientation; 740 rows extend that context set. The 75% bound is newly calculated for all 780. There were 780 zero-buffer crypto calls and no target-mapped plaintext decryptions, because every row was rejected by the bound. The independent verifier rebuilt all five orientations, all 780 matrices and row maxima, matched all 156 base keystreams to the control ledger, checked their exact equality across orientations, and validated configuration/status/summary arithmetic. It made no crypto calls and did not rerun the target search.

Root execution: target chunk31c55a, exit0; independent verifier chunk3bf7ae, exit0. Target runtime reported about0.78seconds, including its synthetic preflight. Do not restart a completed target run.

Artifacts:

- target_results.json: SHA256 18f1404543dc0474c0de38c76d39bbe87243f6f08042e6416a108579cc348a15 (5,401,373 bytes).
- verification.json: SHA256 3c7962a1153c84365ce58a22b520d6def9d804f7373efadd19aa2d58b98f236f.
- authorized target_gate.json: SHA256 f94eca9ca644e4cad576a642590555024d96e44d430e9c6a299decb44c9253e4.
- The deterministic gzip stores the exact complete target JSON, with empty filename and mtime0.

To inspect/verify a fresh checkout, restore the retained JSON without rerunning the experiment, then run the verifier:

```sh
gzip -dk research/rev7-20260909-codex/coverage/hex_substitution_keystream/target_results.json.gz
node research/rev7-20260909-codex/coverage/hex_substitution_keystream/verify_result.js
```

The source and frozen controls, preparation gate and authorized gate, independent audit, verifier, plans and reports are shared alongside the result.

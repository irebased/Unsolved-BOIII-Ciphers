# AMSCO equal-cut4 followed by modern decryption

Identity: ASTRA. The frozen run completed once with 463,680 parameter cells and no retained text/encoding lead. Minimum distinct-byte count was 83; maximum printable count was 75 of 128. Neither crossed the declared retention threshold (D<=69 or printable>=96).

The grid was two input orientations (forward and full hex reversal), all 5040 read-column permutations in a 39x7 rectangle of four-hex-symbol cells, followed by 19 captured block primitives in CFB8 or four captured stream primitives, with keys Zombies/ZOMBIES. A CFB8 window skips one native block then scores 128 bytes, making that window independent of the initial IV. The stream-cipher initialization stays as captured. The direction is conventional transposition DECRYPT only. Other cuts/layouts, the opposite direction, other modern modes or keys, binary inner layers and non-text endpoints are outside this run.

All 92 full-chain cipher/key/orientation plants passed. Encryption deliberately used a different CFB8 IV and the scored plaintext recovered exactly after the skip. All 5040 geometry permutations were checked against an independent column-gather encoder, and the separate Python review checked labelled source indices. Target runtime was 12.711 seconds. Session 70608 completed exit0 and was not restarted.

The result retains full score histograms, an ordered digest of every labelled prefix output, and20 prefixes with highest printable counts. Every flagged candidate would have been fully decrypted and retained; there were none. The auxiliary tie handling keeps a traversal-dependent subset at the final printable-count tie rather than implementing the intended secondary D/ID comparator; REVIEW.md explains this. It does not change counts, extrema, histograms or the zero-hit result. The final seven retained prefixes are a subset of the 13 cases tied at 71 printable bytes; all 13 cases scoring 72 or greater are present.

The initial negative control fixture mistakenly used bytes0..127, which contains 98 printable bytes under the declared rule. It was corrected to128..255 before the control ledger and target source were frozen. No target bytes were involved in that correction.

Reproduce in a fresh directory after obtaining the pinned sibling runtime dependencies:

```sh
node research/rev7-20260909-codex/coverage/amsco44_modern_prefix/search.js --controls
node research/rev7-20260909-codex/coverage/amsco44_modern_prefix/search.js --run-target
```

Both commands refuse existing output files. Do not rerun the completed original. The runtime and its captured WASM sources are published at commit de4c56a57365325c802ceaafa604fbc62b123ebd in the sibling first_layer_occupancy and fable_b64read_source_audit directories.

Source SHA256:eec7380b2ab22db4db523490a75f66a8e0ffa054ac3a95de61b05e5b9a2a4d04. Controls:df09cff8f0db95c405c5583bb593136bd6d736f56b50abf4c27c38d12b1973e5. Result:8f5c03bb222db671db9202f374d0b7a516257cbc6a33bf8bea36ddbd67739fbe. Ordered-output digest:ab3fd40c1ae9811f6a74368cad321402951173f19ad7388add656c349289a955. Independent review:68c70ae87919c36bb6541fc232bb7542778c847fe077d41a366a37b21f866771.

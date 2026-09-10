# Reproduce the partial-observation Bifid exclusion

Identity: ASTRA. This package verifies the completed 31,440-cell target inventory; it does not recover Rev7 plaintext.

The large result is published as a lossless gzip/base64 JSON pack. From this directory, restore it only when the raw file is absent, then replay the independent verifier:

```sh
python3 -B pack_results.py --restore target_results.json
python3 -B verify_results.py
```

If `target_results.json` already exists, use `python3 -B pack_results.py` to verify both copies, then run the verifier. Restore refuses an existing output. The canonical sources and source-certified AMSCO maps are present on this research branch; run the tools within its repository checkout.

The result covers 12 lossy AMSCO maps at natural length 1,310, all four registered display orientations, and every even Bifid period through 1,310. Every missing-symbol completion and square is impossible under the specified 201-codepoint endpoint. The broader Unicode bound leaves 19,786 cells unresolved. Read RESULTS.md for exact limits and hashes. Other natural lengths, source maps, and odd periods below the natural length remain outside the proof.

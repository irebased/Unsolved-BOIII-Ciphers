# Generic lossy-four-digit DES all-IV controls

Identity: **ASTRA**

This synthetic-only package generalizes the audited lossy-`2013` all-IV suffix frontier to each of the 12 distinct source maps at a 1,310-character natural hexadecimal input. The frozen source inventory proves these are the 12 maps among the 336 qualifying positive four-digit keys. Six map classes drop the one-character natural column 1 and expose 4,096 compatible `C[0:8]` registers. Six drop column 3 and expose 256.

`core.py` accepts an explicit emission-index map and derives every byte mask and root domain from it. Roots are processed sequentially. The 100,000 live-frontier limit applies per root; the 5,000,000 accepted-state budget applies globally within one search. Caps are INCOMPLETE and partial-root paths are never terminal solutions. The first eight plaintext bytes and original IV remain unknown.

Controls include one 99-byte planted search for every map class, two 655-byte plants covering both root shapes, one deterministic 1,092-character null per map, tiny cap cases for both root shapes, and independent small-domain generator checks. Each class also proves all four orientation inverses. Search results are reused across those orientations only after proving that inversion returns the byte-identical source observation.

Every terminal candidate retains its full ciphertext and plaintext suffix. Validation uses PyCryptodome DES CFB8 with `C[0:8]` as the suffix IV, a separate manual recurrence, exact hashes and lengths, printable ASCII, and the representative key's literal legacy emission.

The raw ledger intentionally preserves every terminal candidate and is 44,489,987 bytes. `controls.pack.json` is a lossless 2,866,236-byte zlib/base64 transport. Its bounded read-only verifier decompresses in memory, checks the exact raw length/SHA and stream termination, and revalidates all 20,622 terminal candidates without rerunning the frontier. It can emit the exact raw bytes only to a new path.

Verify the transport or unpack it:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy4_alliv_controls/pack_controls.py
python3 -B research/rev7-20260909-codex/lossy4_alliv_controls/pack_controls.py --unpack /tmp/lossy4-controls.json
```

Recompute the full search to a new file or compare a present raw ledger with:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy4_alliv_controls/controls.py --regenerate /tmp/lossy4-controls.json
python3 -B research/rev7-20260909-codex/lossy4_alliv_controls/controls.py
```

No Rev7 ciphertext is read or evaluated, and no target driver or gate is included. A possible later target would have 12 maps by four orientations (48 contexts), of which four `2013` contexts are already covered by the earlier exact scan; that proposal is not executed here.

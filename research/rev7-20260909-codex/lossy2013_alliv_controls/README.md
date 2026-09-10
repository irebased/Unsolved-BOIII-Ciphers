# ASTRA lossy `2013`/`2014` all-IV suffix controls

This synthetic-only package tests a precise consequence of DES CFB8 feedback. Once the first eight ciphertext bytes are known, every later plaintext byte is independent of the original IV. The literal malformed CrypTool keys `2013` and `2014` emit the same observation. Their first-eight-byte masks are `FF,0F,FF,FF,0F,FF,FF,0F`, leaving exactly `16^3 = 4,096` compatible ciphertext registers.

`run.py` enumerates every compatible register in lexicographic order, then runs an exact printable-ASCII (`0x20..0x7E`) masked-CFB8 frontier from byte 8. Roots are processed sequentially. The 100,000 live-frontier limit applies separately to one root; the 5,000,000 accepted-state budget is global across all roots and counts accepted suffix child states, excluding the 4,096 initial registers. A capped result is **INCOMPLETE**. Completed-root terminal solutions remain evidence, while a partial-root path is never labeled a solution.

Controls cover the prior 99-byte and 655-byte plants under distinct nonzero, non-ASCII-zero original IVs, a deterministic 1,092-hex-character null, an independent 4-bit generator oracle, and a deliberately tiny accepted-state cap. Every terminal solution preserves the full ciphertext and plaintext suffix and is checked using PyCryptodome CFB8 with `C[0:8]` as the suffix IV, a separate manual recurrence, and both legacy source emissions. The first eight plaintext bytes and original IV are unknown and are not recovered.

The original provisional files are retained in `drafts/` and are superseded because they did not enforce their global cap or distinguish partial paths from terminal solutions.

Reproduce to a new file and verify the frozen ledger:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy2013_alliv_controls/run.py --regenerate /tmp/lossy2013-alliv.json
python3 -B research/rev7-20260909-codex/lossy2013_alliv_controls/run.py
```

Identity: ASTRA. No Rev7 target data is read or evaluated.

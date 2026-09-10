# Eight-byte-block ragged-B all-IV controls and prospective target

Identity: **ASTRA**.

This directory generalizes the audited unavoidable-full-row-prefix predicate to three 8-byte block primitives:

- DES with key `Zombies\0`;
- standard Blowfish with raw seven-byte key `Zombies`;
- historical libmcrypt Blowfish-compat with raw seven-byte key `Zombies`.

All use CFB8. For `n=546`, widths 2 through 60 have `q=floor(n/w)>8`. For either FABLE ragged convention, `observed[j:q*w:w]` is the guaranteed first `q` bytes of one natural ciphertext chunk. Plaintext from chunk offset 8 onward is independent of the external eight-byte IV. The endpoint begins from states `{0,1,2}` and accepts TAB, LF, CR, printable ASCII, and exactly UTF-8 U+2013, U+2014, U+2018, U+2019, and U+2026. It does not require terminal state zero at the chunk boundary.

One bad unavoidable chunk excludes every column order and every external IV separately for each first-long/last-long convention. The convention weights are parallel and are not added. If every rank retains, the cell remains unresolved. Width 60 exposes one suffix byte; width 61 exposes none and is unsupported.

The historical compatibility adapter calls the compiled pinned libmcrypt source directly. Controls compare its block transform with the independently established word-reversal conjugation and compare a full CFB8 vector with the existing native compatibility harness. For DES and standard Blowfish, the block checks exercise adapter consistency against the same PyCryptodome primitive; they are not independent block implementations. Their manual CFB8 recurrences are compared independently with PyCryptodome MODE_CFB segment size 8. All block fixtures in this active snapshot are synthetic.

Synthetic controls cover live FABLE first/last ragged mappings, arbitrary-IV valid plants with all five punctuation sequences and a UTF-8 sequence crossing the eight-byte boundary, ignored-tail mutation, forced NUL exactly at chunk offset 8 with other ranks unchanged, exhaustive widths 3–6 under two IVs, width 60 positive/negative cases, and width 61 refusal. They do not read Rev7.

Control reproduction:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged8/controls.py
```

The frozen prospective target has 708 contexts: three ciphers, 59 widths, and four canonical orientations. Each cell covers both ragged conventions and every external eight-byte IV. The target remains unexecuted pending explicit authorization.

Gate-only check:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged8/run_target.py --selftest
```

Future authorized command:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/ragged8/run_target.py --run-target
```

The driver stops after the first rejected chunk and stores all ranks examined, the full prefix and suffix, independent two-IV verification, and the first failure. It refuses existing output and checkpoints atomically. This scope does not cover variant A, other modes, keys, ciphers, endpoints, or widths above 60.

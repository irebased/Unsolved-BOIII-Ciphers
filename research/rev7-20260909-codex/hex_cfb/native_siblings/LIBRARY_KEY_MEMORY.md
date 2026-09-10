# libmcrypt fixed-key backing memory audit

Identity: **ASTRA**. This is a source audit; no target was evaluated.

Pinned source: Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`.

- [`lib/mcrypt.c`](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/lib/mcrypt.c), preserved SHA-256 `a9886ec63b7a60be4c3c6be493f4389098cd2bd4805c8c310062acc7cb0fe99f`.
- [`lib/xmemory.c`](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/lib/xmemory.c), preserved SHA-256 `753038b9cc9158c15ac7395ba6af596474cbcaa24948511af19e2e5aca68b2c8`.

`internal_init_mcrypt` obtains the algorithm maximum key size at line 59. Lines 65–94 select the supplied size when supported or the smallest supported size that can hold a short key. For seven input bytes and Loki97 sizes 16, 24, and 32, this selects a declared key size of 16.

Line 97 allocates `keyword_given` with `mxcalloc(1, mcrypt_enc_get_key_size(td))`, using the algorithm maximum size rather than the selected declared size. Line 100 copies only the seven supplied bytes. Lines 124–127 pass this zero-initialized backing buffer and selected length 16 to the algorithm key setup. In `xmemory.c`, lines 63–72 show that `mxcalloc` calls the C library `calloc` directly before optional memory locking.

Therefore historical libmcrypt provides Loki97 with a 32-byte zero-initialized buffer containing `Zombies` followed by 25 NUL bytes and passes key length 16. Loki97 key setup reads eight 32-bit words and ignores its length argument. The source-backed control adapter reproduces library behavior; the 32-byte buffer is not an arbitrary workaround.

RC2 differs: its supported-size list is absent with count zero, so lines 73–76 accept the raw seven-byte length and lines 89–93 retain key size seven. Although the backing allocation still uses RC2 maximum size 128 and is zero-initialized, RC2 key expansion receives length seven and uses only those seven seed bytes before expanding its schedule.

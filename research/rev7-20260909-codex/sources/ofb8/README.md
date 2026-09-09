# libmcrypt 2.5.8 OFB8 source controls

Identity: ASTRA. Target evaluated: false.

This harness compiles the pinned `modules/modes/ofb.c` unchanged and calls its exported mode functions through `ctypes`. Minimal local headers supply only its basic C types and standard includes. PyCryptodome ECB supplies the block-encrypt callback; the mode recurrence is the historical C source.

Run: `python3 research/rev7-20260909-codex/sources/ofb8/run.py`

The 12-row grid is 3 ciphers x 2 IVs x 2 complete plaintext fixtures. Each row records exact key, IV, plaintext, ciphertext, and hashes. Every C output must match a separate Python recurrence for all bytes and round-trip through the actual C decrypt function.

Historical `OFB` is 8-bit OFB: encrypt the register, use encrypted byte zero, shift the old register left one byte, and append that byte. Historical `nOFB` consumes successive encrypted-register bytes and replaces the full register at block boundaries. PyCryptodome `MODE_OFB` controls nOFB/full-block OFB, not this `OFB` module after byte zero.

Pinned sources:
- https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/modes/ofb.c
- https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/modes/nofb.c

No Rev7 input is read or evaluated.


The unmodified upstream mode sources retain their copyright headers. The pinned upstream COPYING.LIB is included alongside them. The local harness and header stubs are separate from the upstream implementation.

# Pinned Blowfish-compat source provenance

`blowfish-compat.c` and `blowfish.h` are unmodified files from Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`:

- https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/blowfish-compat.c
- https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/blowfish.h

The source states that libmcrypt modifications use the libmcrypt license. The accompanying unmodified `COPYING.LIB` is GNU LGPL version 2.1. The small `libdefs.h` and `mcrypt_modules.h` headers are the previously audited minimal local build shims and are hash-pinned by `build_compat.py`.

# Historical source provenance

The `bfcompat`, `twofish`, and `loki97` subdirectories contain the exact algorithm source and minimal build shims copied from Distrotech/libmcrypt commit `3bd338e2f808e985f5b229a7642d48c26615993f`:

- https://github.com/Distrotech/libmcrypt/tree/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms
- Blowfish compatibility: `blowfish-compat.c` and `blowfish.h`
- Twofish: `twofish.c` and `twofish.h`
- Loki97: `loki97.c`

Each directory includes the corresponding `COPYING.LIB` from that repository. It is the GNU Lesser General Public License, version 2.1 or later. The minimal `libdefs.h` and `mcrypt_modules.h` shims expose only the types/macros required to compile the unmodified algorithm source. Exact SHA-256 pins live in `runtime.py` and `controls.json`.

The compatibility relation is checked rather than assumed: historical Blowfish compatibility equals `T(BF_standard(T(block)))`, where `T` reverses bytes within each 32-bit half and preserves the two-half order. Twofish and Loki97 are also gated by their source KATs and frozen solved-source CFB8 evidence.

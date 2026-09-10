# Frozen native binary transport

Identity: ASTRA. The exact macOS ARM64 binary used in the registered run is transported as Base64. Its source, build commands and compiler provenance are in the adjacent build ledger. This binary is platform specific; the original C/C++ source remains available for other builds. A rebuild need not have the identical binary hash across toolchains.

Run `python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/restore_native.py --restore` from the repository root. The helper validates the frozen SHA-256, writes only when absent, and checks an existing file byte-for-byte. Without `--restore` it only verifies. The saved-result verifier expects this exact binary; it does not execute the target search.

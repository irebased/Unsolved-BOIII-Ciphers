# Inert RC2 and Loki97 five-sequence extension

Identity: ASTRA. Target evaluated: false.

This package prepares exactly eight cells: historical source-backed RC2 with raw seven-byte Zombies, and Loki97 with selected key length 16 plus the library-equivalent explicit zeroed 32-byte backing, each under four canonical hexadecimal orientations. Every cell uses CFB8, an ASCII-zero IV, all 16 factorial global hexadecimal-symbol bijections, and a fresh one-billion-node cap.

The terminal endpoint permits TAB, LF, CR, ASCII 32 through 126, and UTF-8 encodings of U+2013, U+2014, U+2018, U+2019, and U+2026. It must finish in state zero.

The frozen native_text5 package already controls both backends against its Python recurrence, complete 256-byte CFB8 streams, seeded four-unknown exhaustive searches, and capped full-mapping prefixes. Its published target evaluated only AES-128, Blowfish, DES, and Blowfish compatibility. RC2 and Loki97 are the two controlled backends absent from that target grid.

preflight.py pins the native engine, source, compiled evidence, controls, endpoint, prototype, key-memory source note, and canonical MDX. It hashes MDX bytes without extracting target ciphertext. Only run_target.py --run-target can parse target text, and that path requires a reviewed authorized target_gate.json.

driver_controls.py uses a synthetic allowed plaintext for both backends and all four orientation selectors. Twelve mappings are seeded, so every cell exhausts exactly 4 factorial mappings. It checks factorial accounting, retains the planted mapping, and independently decrypts, re-encrypts, reconstructs the display, and validates the endpoint through the frozen helpers.

Read-only commands:

    python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_siblings_target/preflight.py
    python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_siblings_target/driver_controls.py
    python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_siblings_target/run_target.py --selftest
    python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_siblings_target/build_gate.py

Regeneration writes only a new path and refuses overwrite:

    python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_siblings_target/driver_controls.py --regenerate /tmp/native_text5_siblings_controls.json

The gate builder requires explicit authorization metadata and a new output path. FABLE message 316 records the plan, not execution authorization. No target gate or target result is included.

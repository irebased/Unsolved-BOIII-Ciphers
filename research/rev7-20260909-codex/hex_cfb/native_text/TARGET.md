# Preregistered native broad-text target extension

Identity: ASTRA.

Status: prepared and control-gated. Rev7 has not been parsed or evaluated by this driver. The self-test hashes the Rev7 MDX file bytes only to bind a future authorized run.

The endpoint is exactly TAB, LF, CR, ASCII 32 through 126, plus UTF-8 `E2 80 93/94/98/99`. A candidate is terminal only in FSA state zero. The ciphers remain AES128 (`Zombies` NUL-padded to 16), Blowfish (raw seven-byte `Zombies`), and DES (`Zombies` NUL-padded to 8), with ASCII-zero IVs and CFB8.

A future authorized run has two ordered phases:

1. Replay all 12 cipher/orientation cells from the root at 10,000,000 DFS entries. Every raw statistic, factorial weight, mapping, and plaintext survivor must exactly match frozen `hex_cfb/results.json` SHA-256 `8c5567bd7cd3d66e926fddd1a5df39b684c29d7387e63418e26104d0fcaab939`. Any mismatch aborts before extension.
2. Run all 12 cells afresh from the root at 100,000,000 entries. The first 10 million nodes are repeated and are not additive.

Rejected plus terminal factorial weight equals 16! only for a complete traversal. A capped row reports an incomplete eliminated-weight lower bound. Every survivor must independently decrypt with PyCryptodome, match the Python manual CFB8 implementation, re-encrypt to the mapped ciphertext, reconstruct the exact oriented display, and finish the endpoint FSA in state zero.

Prepared control-only command:

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/hex_cfb/native_text
python3 -B run_target.py --selftest
```

Future target command, only after GO:

```sh
python3 -B run_target.py --run-target
```

The driver checkpoints atomically after each cell, refuses an existing final output, and requires `--resume` for an existing checkpoint. No cap result claims exhaustive coverage or plant recovery.

## Executed result

The authorized frozen run completed with target ledger SHA-256 `640a1fb9f2878db0c43d2b4e2dbba7d9b8b3f4a77dd87499244c2bdda9c00fe1`. All 12 prior 10M prefixes matched exactly. Of the 12 fresh-root 100M cells, six completed the full 16! certificate and six reached the registered cap; no cell produced a terminal survivor. See `RESULTS.md` for per-cell nodes, certificate weights, unaccounted weights, and timings.

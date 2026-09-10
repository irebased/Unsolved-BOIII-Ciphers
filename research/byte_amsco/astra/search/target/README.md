# Draft byte-AMSCO target harness (ASTRA)

This directory contains an inert driver and synthetic driver controls. It has no target gate or result. The self-test hashes the canonical MDX file but never extracts, parses, or evaluates its ciphertext. Root must preregister the exact scope, create the hash-pinned gate, publish it, and issue a separate GO before the target command can run.

## Exact prospective scope

The driver covers 64 geometries: widths 2–9, starts 1 and 2, and the four canonical byte orientations. Every width permutation is exhausted. The totals are 3,272,896 AMSCO orders and 22,910,272 seven-backend contexts over 546 bytes. Each geometry must finish exactly `width!` orders and `width! × 7` contexts with zero unexamined cases; there is no cap or resume mode. Existing results and checkpoints are refused.

The engine reconstructs a shared ciphertext prefix lazily and tests each fixed-key backend's IV-independent CFB8 suffix. The FSA starts with states `{0,1,2}` at the block boundary and requires state 0 at the true end. Every negative contributes a canonical row to a per-geometry SHA-256 and class/backend counters; only the first three witnesses are retained as examples. Every survivor retains its exact order and complete suffix and is independently full-decrypted and re-encrypted under two IVs.

Checkpoints atomically replace one working file after each completed geometry. The final ledger contains 64 compact cells plus any complete survivors, rather than one row for each of 22.9 million negative contexts. The aggregate negative digest records the deterministic callback output. It does not independently prove complete execution or cryptographically replay every negative.

Driver self-test:

```sh
python3 -S -B research/byte_amsco/astra/search/target/run_target.py --selftest
```

Synthetic controls exhaust complete width-2 and width-3 grids using known plants. They exercise the exact production `scan_cell` callback, counters, negative digest, survivor storage, two-IV reference decryption, and exact re-encryption.

```sh
python3 -S -B research/byte_amsco/astra/search/target/controls.py
```

Regeneration requires PyCryptodome and clang and a new output path:

```sh
python3 -B research/byte_amsco/astra/search/target/controls.py \
  --regenerate /tmp/byte-amsco-target-controls.json
```

## Limits

The registered model is a byte-unit AMSCO analogue with fixed `Zombies` key conventions and ordinary CFB8. It does not cover historical character semantics, other widths, key variants, encodings, framing, padding changes, other modes, or the IV-dependent plaintext prefix. A surviving suffix would be a candidate rather than proof of the intended solution.

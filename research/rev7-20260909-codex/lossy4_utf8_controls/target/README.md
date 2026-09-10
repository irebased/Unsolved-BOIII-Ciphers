# Exact Unicode lossy-map all-IV target driver (inert)

Identity: **ASTRA**. This directory prepares a finite target scan but contains no target result or authorization gate. The target must not run until the reviewed artifacts are preregistered and root gives a separate GO.

## Registered scope

The grid has 48 entirely new endpoint contexts: the 12 frozen 1,310-character CrypTool source-map classes, crossed with `forward`, `full_hex_reverse`, `byte_reverse`, and `nibble_swap`. Every cell reconstructs a 655-byte DES-CFB8 ciphertext with key `Zombies\0`. It enumerates all observation-compatible first eight ciphertext bytes (256 or 4,096 roots), which removes dependence on the unknown original IV for plaintext bytes 8 through 654.

The endpoint is the exact 201-codepoint language from the frozen parent controls: TAB, LF, CR, printable ASCII, U+00A0 through U+00FF, and the seven registered Unicode punctuation characters. The determinized initial state set permits the known suffix to begin inside one UTF-8 codeword. A terminal path is accepted when boundary state 0 is present.

Each cell is capped at 100,000 live paths per root and 5,000,000 accepted states globally. A cap yields `INCOMPLETE`, with completed, partial, and unexamined roots recorded separately. Partial paths never become solutions. Every terminal path from a completed root is retained and independently checked against PyCryptodome CFB8, the manual recurrence, the source emission, and the independent Unicode prefix oracle.

No printable-ASCII negative is reused as a Unicode negative. All 48 contexts are scheduled as new searches. The frozen 4,096-root full-length synthetic control is explicitly incomplete at five million accepted states. The separate one-root seeded control recovers its planted truth, but supplies only a synthetic mechanics check and no all-roots or target coverage.

## Read-only checks

From the worktree root:

```sh
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/target/driver_controls.py
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/target/run_target.py
```

The first command recomputes compact synthetic driver controls and verifies the frozen ledger. The second hashes the target sources without extracting or evaluating the Rev7 ciphertext. It also validates a gate if one later exists.

After external preregistration, root can create a reviewed gate at a new path:

```sh
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/target/prepare_gate.py --fable-reference 'EXACT EXTERNAL REFERENCE' --output /tmp/target_gate.json
```

Creating a gate does not evaluate the target. The eventual target command is intentionally omitted until separate authorization.

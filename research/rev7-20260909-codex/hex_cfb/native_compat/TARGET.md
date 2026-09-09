# Preregistered BF-compat target run

Identity: **ASTRA**. Target evaluated: **false**.

## Frozen hypothesis and grid

The four cells use the pinned libmcrypt Blowfish-compat block primitive with the raw seven-byte key `Zombies`, CFB8, and the eight-byte ASCII-zero IV `3030303030303030`. The input orientations are `forward`, `reverse`, `byte_reverse`, and `nibble_swap`. Each cell starts at the DFS root and stops at 1,000,000,000 visited nodes unless its exact 16! mapping certificate completes first. Runs are independent and their caps are not additive.

The endpoint accepts TAB, LF, CR, bytes 32 through 126, and only UTF-8 sequences E2 80 93, E2 80 94, E2 80 98, and E2 80 99. A retained plaintext must terminate in FSA state zero. A capped cell establishes only its recorded eliminated mapping weight and leaves the reported remainder uncovered.

## Controls and validation

`target_gate.json` freezes the C++ engine and binary, Python prototype and controls, 200 reference vectors, saved source reproduction harness and ledger, pinned unmodified libmcrypt source and minimal headers, both compiled source libraries, ABI record, and Rev7 container bytes. The source reproduction directly checks the raw seven-byte key against the actual compiled compatibility primitive. The prior controls establish exact native/Python DFS parity, seeded factorial coverage, cap semantics, CFB8 equivalence, and punctuation FSA behavior. No synthetic prefix replay is part of this run.

For every retained target survivor, `run_target.py` reconstructs all ciphertext bytes from the candidate nibble permutation. It then decrypts and re-encrypts with (1) the actual compiled unmodified libmcrypt compatibility ECB primitive inside a separate manual CFB8 loop and (2) an independent Python word-reversal Blowfish adapter inside its manual CFB8 loop. It also checks exact inverse nibble-map display reconstruction and terminal FSA state zero.

## Commands

Preparation-only check (does not parse or evaluate Rev7):

    python3 -B research/rev7-20260909-codex/hex_cfb/native_compat/run_target.py --selftest

After a separately posted public plan and explicit GO, execute once from the worktree root:

    python3 -B research/rev7-20260909-codex/hex_cfb/native_compat/run_target.py --run-target

The driver refuses an existing final result. It writes an atomic checkpoint after every cell; `--resume` is required to continue an existing checkpoint. No target command has been run during preparation.

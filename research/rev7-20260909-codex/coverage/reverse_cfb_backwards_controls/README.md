# Reverse-CFB8 backwards reconstruction controls

Identity: **ASTRA**. This synthetic-only package checks the finite backwards recurrence preregistered in ASTRA bus message 328. It reads no Rev7 data and performs no target or corpus scan.

## Model and proof

Let readable bytes `P` be supplied as the ciphertext input to ordinary CFB8 decryption under a hidden IV, producing observed bytes `X`. Immediately before processing byte `P[i-1]`, the register is `R_(i-1)`, and immediately afterward it is `R_i = P[i-b:i]` once `i >= b`. Therefore

```text
X[i-1] = P[i-1] XOR E_key(R_(i-1))[0]
R_(i-1) = z || R_i[:-1]
E_key(R_(i-1))[0] = X[i-1] XOR R_i[-1]
```

Given one complete `b`-byte crib in `P`, every predecessor can be enumerated exactly. For `i>b`, `z` is an earlier `P` byte and is restricted to TAB, LF, CR, or ASCII 32 through 126. For `i<=b`, `z` is an original-IV byte, so all 256 values are enumerated. These predecessor branches are disjoint because each chooses a concrete byte. After reaching the initial register, the rest of `P` is reconstructed uniquely forward from `X` and the crib register.

The search keeps every branch. It has no score or beam. A limit of 100,000 live branches or 1,000,000 ECB calls yields `INCOMPLETE`; a partial branch is never reported as a solution.

## Controls

One DES plant and one standard-Blowfish plant use raw fixed `Zombies` key conventions, deterministic nontrivial hidden IVs, readable paragraphs longer than 100 bytes, and an eight-byte crib at offset 17. The exact planted `P` and IV occur once among all survivors. Every surviving pair is checked by PyCryptodome CFB8 decryption, manual CFB8 recurrence, reverse library encryption, exact crib placement, and both library and manual forward suffix reconstruction.

Twenty-four smaller forward checks cover both ciphers, two IVs, and crib offsets 0, 1, 7, 8, 17, and 31. Tiny one-call controls prove that caps are labeled incomplete without emitting partial solutions.

Run the deterministic read-only replay from the worktree root:

```sh
python3 -B research/rev7-20260909-codex/coverage/reverse_cfb_backwards_controls/control.py
```

To regenerate to a new path without overwriting evidence:

```sh
python3 -B research/rev7-20260909-codex/coverage/reverse_cfb_backwards_controls/control.py --regenerate /tmp/reverse-cfb-controls.json
```

## Limits

This demonstrates mechanics for DES and standard Blowfish with fixed keys and an exact known register. It assumes `P`, rather than `X`, belongs to the declared byte alphabet. It does not recover an arbitrary unknown crib, relax the alphabet, test other modes or transforms, or evaluate Rev7.

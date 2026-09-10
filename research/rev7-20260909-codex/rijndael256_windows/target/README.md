# Rijndael-256 window target driver — inert draft (ASTRA)

This directory prepares a finite 24-cell target run but contains no gate or result. Running the target requires a gate created after an exact FABLE preregistration and a separate root GO.

The frozen scope is three explicit keys (`Zombies` followed by NUL to 16, 24, or 32 bytes), four byte orientations, and ECB/CBC. Each 546-byte oriented stream contributes 483 ECB windows and 451 CBC windows, for 11,208 context rows. The ECB hypothesis decrypts two complete 32-byte blocks. The CBC hypothesis reads `C0 || C1 || C2` and returns the IV-independent `D(C1) xor C0 || D(C2) xor C1`. These are alignment hypotheses; no bytes are added, stripped, trimmed, padded, or unpadded.

Every context row stores its full 64 plaintext bytes, both decrypted blocks, input-window SHA-256, classification, and rejection witness. Every retained candidate is independently replayed through the untouched JavaScript block source and a separate cut-boundary regex oracle. The registered endpoint permits the five UTF-8 punctuation sequences and uses initial and terminal states `{0,1,2}` because both window edges are cuts.

The driver builds the pinned C source in a temporary directory. Results record the portable source hash and normalized build command, not a machine-specific binary hash. It refuses pre-existing output or checkpoint files and has no resume or cap.

Synthetic driver controls use the same `execute_cell` path on complete 546-byte ECB and CBC plants, verify all row accounting and evidence fields, and independently replay the retained window. They do not read Rev7.

Read-only synthetic verification:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_windows/target/controls.py
```

Driver self-test hashes the canonical MDX bytes only:

```sh
python3 -S -B research/rev7-20260909-codex/rijndael256_windows/target/run_target.py --selftest
```

An authorized gate can later be written to a new path with:

```sh
python3 -B research/rev7-20260909-codex/rijndael256_windows/target/prepare_gate.py --fable-reference '<exact reference>' --output /tmp/target_gate.json
```

The package makes no target claim until the gated run is separately authorized and completed. A post-run lossless pack may reduce publication size while preserving every row.

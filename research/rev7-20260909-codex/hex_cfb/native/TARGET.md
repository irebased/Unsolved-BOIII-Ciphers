# Preregistered native target extension

Identity: ASTRA.

Status: prepared and control-gated; Rev7 has not been parsed or evaluated by
this driver. The self-test hashes the Rev7 source file bytes to bind the future
run to the registered input. It does not extract or decrypt the ciphertext.

The endpoint is exactly 69 bytes: ASCII letters, decimal digits, `+/=`, space,
TAB, LF, and CR. The registered ciphers and key/IV conventions remain AES128
(`Zombies` NUL-padded to 16), Blowfish (raw seven-byte `Zombies`), and DES
(`Zombies` NUL-padded to 8), all with ASCII-zero IVs.

A future explicitly authorized run has two ordered phases:

1. Replay all 12 cipher/orientation cells from a fresh root at 3,000,000 DFS
   entries. Every raw counter, factorial weight, mapping, and plaintext survivor
   must exactly equal the frozen Python ledger. A mismatch stops the run before
   extension.
2. Run only the six formerly capped forward and nibble-swap cells from a fresh
   root at 100,000,000 DFS entries each. The 3M work is a repeated prefix and
   is never added to nodes or certificate weights.

A complete result requires rejected plus terminal factorial weight to equal
16!. A capped result reports the certificate weight only as a lower bound on
eliminated full mappings. Every terminal survivor is independently decrypted
and re-encrypted with PyCryptodome CFB8, checked with the manual CFB8 routine,
and reconstructed through the global display map.

Prepared control-only command:

```sh
cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/hex_cfb/native
python3 -B run_target.py --selftest
```

Future target command, only after GO:

```sh
python3 -B run_target.py --run-target
```

The driver refuses an existing final output, checkpoints atomically after every
prefix and extension cell, and requires `--resume` to continue an existing
checkpoint. Frozen artifacts include the native source and binary, native
control source/result, Python prototype, imported encoded driver, original 3M
target ledger, driver source, gate, and Rev7 MDX byte hashes.


## Completed result

The authorized run completed successfully. All 12 prefix replays matched the
frozen Python ledger exactly. The six extended cells finished between
13,079,776 and 13,878,204 DFS entries, below the 100M cap, with full `16!`
certificates and zero survivors. Together with the six previously complete
reverse and byte-reverse cells, all 12 registered Base64/CFB8 cells are now
exhaustive. See `RESULTS.md`; `target_results.json` has SHA-256
`74ce86bd01c4bbeb1492f61707039d07884ac7c3d9b63ec20bde5ea3d9301644`.

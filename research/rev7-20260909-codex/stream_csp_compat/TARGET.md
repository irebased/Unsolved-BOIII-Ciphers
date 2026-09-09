# Preregistered Blowfish-compat OFB target grid

Identity: ASTRA. Status: control-gated and not run.

The fixed grid contains 24 cells: the pinned libmcrypt Blowfish-compat block
primitive with raw seven-byte Zombies key; historical OFB8 and full-block OFB;
ASCII-zero, NUL, and SHA-1(raw Zombies) prefix-eight IVs; and forward, reverse,
byte-reverse, and nibble-swap orientations. Each cell has a 1,000,000
accepted-CSP-node cap.

The target solver is the frozen stream_csp core. Validation is implemented
separately in this driver: it loads the actual compiled pinned compatibility C
primitive, generates the fixed keystream through a separate recurrence, locally
decodes and re-encodes the display map, directly XORs and reciphers every
survivor, and applies a local endpoint FSA. Full-block OFB is additionally
matched against the independently conjugated standard PyCryptodome stream.

For any unrestricted repeated-pair witness, the driver directly enumerates all
256 possible ciphertext-byte values and asserts that none satisfies every
listed position. This argument is recorded separately from the global
16-symbol bijection certificate. The latter reports rejected and relaxed
terminal bijections and requires their sum to equal 16! before a cell is called
complete. A capped certificate remains incomplete.

Control-only gate:

    python3 -B run_target.py --selftest

Future target command, only after explicit GO:

    python3 -B run_target.py --run-target

The driver refuses existing final output, checkpoints atomically after every
cell, and requires --resume for an existing checkpoint. Frozen hashes bind the
compatibility stream and control sources, control ledger, CSP core, orientation
prototype, pinned source-check reproduction and compiled compatibility
primitive, actual historical OFB8 harness, and canonical Rev7 MDX bytes.

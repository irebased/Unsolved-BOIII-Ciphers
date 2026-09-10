# Inert TEA target harness

Identity: ASTRA. This unexecuted harness defines exactly 160 direct TEA contexts: five orientations, BE/LE word packing, `Zombies`/`ZOMBIES` NUL-padded to 16 bytes, null/ASCII-zero 8-byte IV, and CFB8/full-block CFB/full-block OFB/CTR. The fifth orientation reverses the 219 visible tokens while preserving token interiors. It retains every 546-byte result and its full histogram and endpoint flags.

`driver_controls.py` generates a separate ciphertext for every cell and recovers the same mixed UTF-8 plant, including the non-involutive visible-token geometry. `run_target.py` does not read the target unless `--run-target` is passed and a root-created reviewed gate exists. `prepare_gate.py` is intentionally inert. No target evaluation has occurred.

This target proposal was superseded before execution by later retained evidence that FABLE had already completed a broader direct TEA sweep. Do not create a gate or run it as new coverage.

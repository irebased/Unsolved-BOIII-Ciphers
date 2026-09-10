# Inert lossy-2013 target driver

Identity: **ASTRA**

This driver defines one source-equivalent emission model for literal CrypTool keys `2013` and `2014`; they are not counted twice. The exact grid is:

- 655 natural ciphertext bytes reconstructed from 1092 observed hex characters;
- four canonical observed-hex orientations;
- DES and AES-128 with the source-controlled Zombies key conventions;
- NUL and ASCII-`0` IVs for each cipher;
- printable ASCII bytes 32 through 126;
- 100,000 frontier and 5,000,000 cumulative-state caps.

There are 16 contexts. Every complete compatible plaintext/ciphertext path is retained. The search has no score or language pruning. Any cap is `INCOMPLETE`.

Default self-test hashes the canonical MDX and dataset but does not extract or evaluate Rev7:

```sh
python3 -B research/char_amsco/astra/lossy2013/target/run_target.py --selftest
```

Synthetic driver controls exercise the exact context evaluator on a 655-byte mixed-case printable plant across all 16 paths:

```sh
python3 -B research/char_amsco/astra/lossy2013/target/driver_controls.py
```

The target command must not run until a reviewed gate records public preregistration and root separately issues GO. The driver refuses an existing result or temporary output before extracting the target.

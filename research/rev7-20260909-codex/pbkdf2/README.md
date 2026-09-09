# ASTRA015 reproduction

This directory contains the bounded PBKDF2-derived-key experiment announced at
<https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5608806319>.
See `PLAN.md` for exact derivation, mode, grid, detector, source, and limitation
details.

The controls-only checkpoint is:

```sh
python3 -B run.py --controls
```

After the public plan was posted, the authorized target command was:

```sh
python3 -B run.py --target
```

`--target` always reruns and asserts every control before reading Rev7. It then
preserves every complete 546-byte output as hexadecimal in `results.json`.
There is no installation step or external runtime dependency beyond the
recorded Python and PyCryptodome versions. Passing controls validate the exact
derived-key and mode conventions implemented here; they do not prove complete
historical PHP-wrapper equivalence.

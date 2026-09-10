# Inert numeric Pollux target harness (ASTRA)

This directory contains a 16-context target driver and its synthetic wiring controls. The target has not been run. FABLE message 221 records the plan; a separate root GO remains required.

The exact model is:

- the two historical numeric UI boards: plain and multiply-by-7;
- decimal digits in forward or whole-string reverse order;
- the four canonical hex orientations;
- whole decimal integer to uppercase even-length hex representation;
- no inserted or restored decimal zero;
- a necessary Morse language consisting of any of the 44 literal source-table codewords, in a nonempty sequence separated by exactly one Morse space.

The driver retains every context's complete decimal digit string and complete decoded Morse string. A rejection records the first empty stream, leading separator, trailing separator, empty internal token, or invalid-token witness with its exact offset. Every accepted string is retained without scoring or cutoff. Exact whole-integer re-encryption is required in all contexts. There is no cryptography.

The self-test hashes the MDX and dataset files and validates the frozen source/control package without extracting or converting target ciphertext:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/target/run_target.py --selftest
```

The portable driver-control verifier checks 16 existing synthetic control rows through the exact evaluation function and all five witness classes:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/target/driver_controls.py
```

The gated target command remains unauthorized until root issues GO:

```sh
python3 -S -B research/rev7-20260909-codex/homophonic/pollux_source/target/run_target.py --run-target
```

Existing target output is refused.

This necessary-language test is intentionally broader than exact frontend-produced text because it accepts all 44 Morse table tokens, including frontend-unreachable entries. A failure excludes only this exact two-board representation model. It does not cover alphabetic or mixed UI boards, generic class assignments, radix-26/36, extra zero restoration, or permissive low-level `fromMorse` aliasing.

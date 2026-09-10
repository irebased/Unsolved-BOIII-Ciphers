# CrypTool100 finite target driver (inert)

This directory contains a synthetic-tested driver for 64,000 candidates: four hex involutions, four even-length decimal involutions, 40 coprime multipliers, and 100 rotations. It does not evaluate Rev7 without an immutable source-matched gate and a separate root GO. Default execution hashes the MDX and dataset only. Existing target output is refused.

For each representation path the driver converts the whole oriented hexadecimal integer to a minimal decimal string, prepends one zero only when required to restore two-digit phase, applies the selected decimal involution, and decodes every pair through every historical board. Every candidate plaintext is retained in deterministic NDJSON. Scores only order the separately reported top 20 per path.

Exact verification reuses the observed two-digit codes: each code must belong to its decoded letter under the board, and applying the registered decimal transform, whole-integer conversion, one-nibble hex parity pad, and hex transform must reproduce the canonical input exactly. It never re-encodes by choosing a new random homophone. Additional lost `00` pairs remain an unknown plaintext prefix for identity/pair-internal swap, or suffix for whole-digit/pair-order reversal.

Synthetic controls cover all 16 representation paths, one full 4,000-board cell, exact candidate IDs and membership/reconstruction, and directed leading-zero loss at both ends.

```sh
python3 -B research/rev7-20260909-codex/homophonic/cryptool100/target/driver_controls.py
python3 -B research/rev7-20260909-codex/homophonic/cryptool100/target/run_target.py
```

# Inert target plan

Identity: ASTRA. No Rev7 target result exists and execution requires a separately reviewed `target_gate.json` with explicit root GO.

The exact stage evaluates 1,440 cells: four canonical orientations, big/little unsigned limb interpretation, forward/reverse limb order, forward/reverse complete digit direction, and all 45 ordinary two-header checkerboards. The 546 bytes become 136 fixed-width 10-digit u32 limbs and one exact fixed-width five-digit u16 tail. Every complete parse, exact token-sequence hash, token count, distinct count and IoC is retained. The headers 3/7 row is also decoded through the documented Rev3 board when it avoids the two unpopulated cells, with exact reconstruction.

The plaintext-producing stage deduplicates exact token sequences, ranks them by token IoC, and retains the stable first 20. Each gets four deterministic 6,000-step annealing restarts over `ABCDEFGHIJKLMNOPQRSTUVWXYZ .`; every mapping, score and complete plaintext is retained and reconstructed from the token stream. The matching 850-token benchmark projects 54.85 seconds. This is deliberately heuristic and supplies leads, never a finite alphabet exclusion.

Preflight without target access:

```sh
python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/run_target.py
python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/driver_controls.py
```

After source review, preregistration and a separate root GO, the sole target command would be:

```sh
python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/run_target.py --run-target
```

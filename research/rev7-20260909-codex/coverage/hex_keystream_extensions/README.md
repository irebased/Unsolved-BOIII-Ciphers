# Fixed-keystream hex-map extensions (ASTRA)

This package extends the controlled global 16-symbol displayed-hex bijection model in `../hex_substitution_keystream/`. It is incremental: the full-OFB, CTR, Panama, and Arcfour rows for `Zombies` and `ZOMBIES` belong to the earlier 780-cell package and are not repeated here.

## Registered scope

The inert target grid has 2,700 cells over five canonical orientations.

- Family A has 1,560 cells: all 19 block primitives in full-block OFB and CTR, using the four new literal keys `Zombie`, `ZOMBIE`, `zombie`, and `zombies`, two IVs, and five orientations; plus Panama and Arcfour with those four keys and five orientations.
- Family B has 1,140 cells: all 19 block primitives in historical 8-bit OFB, all six literal keys (`Zombies`, `ZOMBIES`, and the four additions), two IVs, and five orientations.

The IV is either all-zero bytes or ASCII `0` bytes at the primitive block size. Loki97 receives the explicit 32-byte zero-backed key buffer used by the controlled runtime. The endpoint is exactly TAB, LF, CR, and ASCII bytes 32 through 126.

## OFB8 recurrence

The captured libmcrypt `ofb.c` defines 8-bit OFB. Starting with register `R=IV`, each byte is:

```text
E = ECB_encrypt(key, R)
K[i] = E[0]
R = R[1:] || K[i]
P[i] = C[i] XOR K[i]
```

The wrapper does not expose historical OFB8 as a mode. The package therefore calls the actual pinned WASM block primitive through its ECB-encrypt entry point for each recurrence step. Controls compare complete 256-byte AES, DES, and Blowfish streams for all six keys with an independent PyCryptodome implementation. The `Zombies` cases also match six preserved vectors from the unmodified compiled historical `ofb.c` harness. Blowfish with `Zombies` and the zero IV is an intentional all-zero-keystream control.

## Bounds

The earlier sound row-max bound is retained. For each displayed high symbol `a`, `W[a][v]` counts positions whose plaintext high nibble is compatible with the endpoint under assignment `g(a)=v`. The sum of independent row maxima is an upper bound on endpoint bytes.

When that bound does not already exclude 75 percent ASCII, this extension computes the exact maximum-weight bijective assignment for the saved 16 by 16 matrix. This tightens the high-nibble relaxation while still ignoring low-nibble restrictions. A saved mapping and its 16 row contributions certify the assignment value. Eight controlled 4! instances independently enumerate every assignment.

The ordered-pair relaxation and exact full-ASCII CSP are used only after the injective high bound remains weak. CSP UNSAT excludes 100-percent ASCII only; it is never reported as a 75-percent exclusion.

## Source support and limits

Full-block OFB and CTR are fixed-keystream constructions in the captured wrapper source. Historical OFB8 is supported by the captured upstream mode recurrence plus actual pinned ECB primitives. Panama and Arcfour remain empirically controlled fixed-keystream models because their underlying algorithm C sources are absent from the captured publication; their 40 cells are reported separately.

A negative covers only the exact key, IV, mode, orientation, global bijection, and 98-byte endpoint. It does not cover feedback modes, changing maps, other encodings, or inserted transformations. Bound values at or above the threshold remain unresolved unless a stronger weighted bound proves otherwise.

## Commands

Controls and source verification:

```sh
node research/rev7-20260909-codex/coverage/hex_keystream_extensions/controls.js
```

Target-free preflight:

```sh
node research/rev7-20260909-codex/coverage/hex_keystream_extensions/run_target.js
```

The target command is inert until a reviewed gate explicitly grants it:

```sh
node research/rev7-20260909-codex/coverage/hex_keystream_extensions/run_target.js --run-target
```

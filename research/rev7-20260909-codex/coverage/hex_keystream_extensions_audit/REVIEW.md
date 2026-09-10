# Hex-keystream extension source review

Identity: **ASTRA**. Target-free independent review; no Rev7 evaluation.

No correctness blocker was found in the reviewed extension sources.

`runtime.js` implements historical 8-bit OFB as `v=ECB_encrypt(register)[0]`, emits `v`, shifts the register left by one byte, and appends `v`. This agrees exactly with the pinned libmcrypt `ofb.c` `_mcrypt` and `_mdecrypt` loops. The wrapper ECB call receives exactly one aligned block, so its encryption padding path does not change length. Each call clears and reloads the key buffer; IV memory is irrelevant to ECB and is explicitly cleared. Literal six/seven-byte keys and the special 32-byte Loki97 backing agree with the frozen first-layer runtime conventions.

The controls compare AES, DES, and Blowfish streams against an independent PyCryptodome recurrence for all six key spellings and both IVs. Six prior compiled historical-C vectors under `Zombies` also agree. This independently anchors the mode recurrence and three representative primitive adapters. Other block primitives use the same audited recurrence around their actual wrapper ECB encryption; that is a source-backed construction, not a claim of independent primitive conformance.

`assignmentUpperFromMatrix` is exact maximum-weight perfect matching over the saved `16x16` high-nibble matrix. Its DP state is the set of consumed nibble values after assigning rows in fixed order. Every transition adds one unused value; the terminal full mask therefore considers every bijection. Parent reconstruction follows the saved chosen value backward one row at a time. Scores are small integers, so `Float64` is exact here. The result is a sound bound no larger than the independent row-maximum relaxation.

The analysis order is also sound: compute the row-max bound; if weak, tighten it with the exact assignment bound; if still weak, compute the ordered-pair relaxation. A bound below `ceil(0.75*N)` is conclusive. A bound at or above the threshold stays unresolved for the 75% question, even if the separate full-ASCII CSP is UNSAT.

Reviewed hashes:

- `runtime.js`: `9577225bb8b8e21b0cc7ddfff1c2e4f6c6d090661abe8ad95216f8a73a08ab47`
- `model.js`: `4c7e05c8a692fd0e4dd5721b82052d6864f95ae94bc9bf5fc52dbf93ba130651`
- `ofb8_pyref.py`: `e60386a1fbddf60bec1e6cec5db72602a064820e79755b1128fafda74953c21d`
- `controls.js`: `e171f96017c053e9f454cf12a0696c6f09500ec3a290e65cbbf27b532c0b6154`
- `controls.json`: `237a2a5f403ab33cde275c33dd664afceed267e389f6fd2b7662c8a7903d9c14`
- pinned historical `ofb.c`: `aec1699eecb37e4791e704d074e88fbe210f62dd75e6c1face8a5fc302ee926d`

Limits: Panama and Arcfour remain behaviorally controlled because their underlying compiled C module sources were not captured. The package excludes Enigma and WAKE. It covers only the six listed literal keys, two IVs, fixed XOR keystream semantics, five orientations, and the ASCII98 endpoint.

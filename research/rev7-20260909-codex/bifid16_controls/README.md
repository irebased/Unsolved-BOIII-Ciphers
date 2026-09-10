# Arbitrary-square 4x4 Bifid controls

Identity: ASTRA. Target evaluated: false. No Rev7 input was read.

The concrete implementation generalizes the pinned 2008 CrypTool Bifid coordinate split/interleave convention from its historical 5x5 square to an explicitly declared 4x4 hexadecimal alphabet. Period blocks reset independently, and the last short block uses its own length. The SMT model uses sixteen bounded integer square-position variables, AllDifferent, integer row/column extraction, and a finite inverse lookup. No symmetry breaking is applied.

Completed evidence:

- 48 deterministic concrete encrypt/decrypt round trips cover periods 1, 2, 3, 5, 16, and 31 and varied final short blocks.
- With twelve symbol positions frozen, all 24 remaining square completions were independently enumerated. The complete endpoint-valid concrete and SMT model sets agree exactly; two models survive.
- A fully fixed square gives the same concrete and SMT plaintext.
- Contradictory equal positions under AllDifferent return UNSAT.
- A 546-byte period-31 plant with the truth square fixed returns SAT, yields the exact concrete plaintext, and re-encrypts exactly.

The full unknown-square period-31 endpoint model reached its registered 120-second timeout and returned unknown. A period-2 attempt likewise returned unknown, and a period-3 attempt was manually interrupted after roughly 90 seconds without a result. These are incomplete performance observations, never negative results. No model was retained from them. attempts.json preserves their exact status and input hashes.

The period-31 SMT formula is retained in full_plant.smt2. The initial integer div/mod encoding is mathematically direct but performs poorly on the full unknown-square case. Later bit-vector byte-bag controls, if present, are a separately labeled relaxation and do not change this endpoint result.

The historical PHP source is copied unchanged as source/functions.bifid.php. It establishes the coordinate-string operations but did not itself offer a 4x4 square; that generalization is part of this declared hypothesis.

Run the read-only evidence verifier with:

    python3 -B research/rev7-20260909-codex/bifid16_controls/verify.py

Limits: SAT means one compatible square/plaintext model unless enumeration is explicitly complete. Unknown or interrupted means unresolved. Only UNSAT is a proof of exclusion. No target driver is included.

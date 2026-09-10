# Bifid16 one-square coverage reconciliation

Identity: **ASTRA**. This is a read-only reconciliation, not a new target search. The completion process was still running when this note was prepared, so the conditional conclusion below is not yet a final family result.

## Exact universe and evidence partition

The registered universe is 4 canonical orientations × periods 1 through 1092 = **4,368 labeled cells**. The model applies one arbitrary fixed 4×4 square directly to the oriented 1,092-symbol ciphertext; the resulting nibbles are paired into 546 candidate plaintext bytes.

The square-independent even-block invariant already excludes all **2,184 even-period cells** for the exact 201-codepoint endpoint's 165-byte union. This includes the seven cells that were unresolved only under the broader 213-byte union. Evidence: `even_target/RESULTS.md` lines 7–18 and its pinned result SHA-256 `acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8`.

The odd pilot and full-bag follow-up together exclude **16 odd cells** under bag213: periods 3, 31, 99, and 1091 across all four orientations. Evidence: `odd_fullbag/RESULTS.md` lines 3–13 and pinned result SHA-256 `3bbb8ccd756ea29082b2394108544601c79eb0fe19d2259b2c8ba732294225a3`.

The completion driver derives the remaining **2,175 fresh cells** as 2,168 odd cells plus the seven broad-213 even residuals (`complete_periods/run_target.py` lines 26–33). For a final narrow-endpoint reconciliation, results for those seven even cells are unnecessary because the 165-byte invariant already excludes them. The only outstanding logical requirement is a terminal, independently verified **UNSAT result under bag213 for all 2,168 fresh odd cells**.

If that requirement is met, the disjoint narrow-endpoint accounting is:

- 2,184 even cells excluded directly at bag165;
- 16 previously solved odd cells excluded at bag213;
- 2,168 completion-run odd cells excluded at bag213;
- total: **4,368 / 4,368** cells.

## Endpoint inclusion

The exact endpoint byte union is `{9,10,13} ∪ [32,126] ∪ [128,191] ∪ {0xC2,0xC3,0xE2}`, size 165. The solver's broad union is `{9,10,13} ∪ [32,126] ∪ [128,191] ∪ [0xC2,0xF4]`, size 213 (`complete_periods/run_target.py` lines 9 and 13). Direct set reconstruction gives strict inclusion **bag165 ⊂ bag213**, with 48 additional bytes and no byte in bag165 missing from bag213. Therefore UNSAT for bag213 implies UNSAT for bag165; the converse is not required.

## Pending state observed

At the read-only snapshot, `complete_periods/status.json` reported **1,482 / 2,175** fresh cells processed: 1,477 UNSAT, 0 SAT, and 5 UNKNOWN. The checkpoint showed every processed odd cell UNSAT (1,477); the five UNKNOWN cells were even residuals: `forward` 562/972, `reverse` 16/514, and `byte_reverse` 16. There were **691 fresh odd cells and two even residual cells still pending** at that instant. This snapshot can change while the authorized process continues and is not a final certificate.

## Claim boundary

A verified terminal run with all fresh odd cells UNSAT would close this exact **one-square 4×4 Bifid** family for four orientations, periods 1–1092, and the 201-codepoint endpoint. Period 1092 also represents nominal periods at or above the message length only insofar as they form the same single block.

The even invariant separately proves a specific construction with two fixed coordinate squares, but the odd SMT solver is one-square. Consequently a full all-period reconciliation must be stated only for the one-square family. It does not cover general two-square/Four-square algorithms, changing squares by block, Bifid placed before or after another cipher or lossy transform, other orientations, other plaintext alphabets, or all classical ciphers.

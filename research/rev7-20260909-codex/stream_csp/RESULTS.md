# Fixed-keystream stream-CSP target results

Identity: ASTRA. Completed 2026-09-10 with the preregistered command:

    cd /private/tmp/rev7-astra-20260909
    python3 -B research/rev7-20260909-codex/stream_csp/run_target.py --run-target

All 72 registered cells completed below the 1,000,000-node cap. Each cell has
rejected plus terminal factorial weight equal to 16!, or
20,922,789,888,000. There were zero relaxed relation survivors and zero final
FSA survivors.

Sixty-eight cells were inconsistent during root propagation and visited zero
accepted CSP nodes. Each of those cells also has an unrestricted repeated-pair
witness: even if a displayed pair could map to any one of 256 ciphertext bytes,
without nibble or global-bijection restrictions, no single byte makes all
listed occurrences pass the relaxed byte predicate.

One compact example is AES128 / historical OFB8 / ASCII-zero IV / forward.
Displayed pair 00 occurs at byte positions 18, 192, and 198 with keystream bytes
5c, bc, and 30. Intersecting the unrestricted sets

    {c in 0..255 : (c XOR keystream[position]) is relaxed}

over those three positions is empty.

The other four cells were Blowfish / historical OFB8 / NUL IV in the four
orientations. Each exhausted the full mapping space in 518 accepted CSP nodes,
with no relaxed survivor:

| Orientation | Accepted nodes | Seconds |
| --- | ---: | ---: |
| forward | 518 | 3.151458 |
| reverse | 518 | 2.779785 |
| byte reverse | 518 | 2.864287 |
| nibble swap | 518 | 2.854432 |

Their 226 ordered-pair relations had sizes from 7 through 97, so these results
come from all-different CSP exhaustion rather than an empty individual relation.

Summed solver time was 12.801572 seconds: 1.151610 seconds for the 68 root-unsat
cells and 11.649962 seconds for the four 518-node cells.

The finite negative result covers exactly three registered ciphers, historical
OFB8 and full-block OFB, three registered IV constructions, four orientations,
a global bijection of the 16 displayed hex symbols, and the documented
ASCII-plus-four-UTF-8-punctuation endpoint. It does not cover CTR, other stream
recurrences, keys, IVs, orientations, or endpoint alphabets.

Artifact:

- target_results.json SHA-256:
  f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87


## Independent contradiction verification

`verify_witnesses.py` recomputes all 18 distinct keystreams through the unchanged compiled libmcrypt C OFB8 mode or PyCryptodome full-block OFB, without importing the CSP solver. All keystream hashes match. For 68 cells, it checks every one of the 256 possible mapped bytes against each saved repeated-pair witness; none survives. These witnesses exclude even a nonbijective fixed displayed-byte mapping in those 68 contexts.

The remaining four cells are Blowfish/OFB8 with the NUL IV. The first byte of ECB-encrypted all-zero register is zero, so the register and OFB8 keystream remain all zero. The observed stream contains 226 distinct displayed byte pairs, while the relaxed endpoint permits only 104 distinct bytes. Every bijective byte substitution preserves the former count and therefore fails. Thus all 72 contexts also exclude arbitrary global byte permutations, a larger class than the original nibble-bijection search. This stronger conclusion follows from the independently checked witnesses/counting argument, not from a claim that the CSP enumerated 256! mappings.

Frozen independent verification: `witness_verification.json`, SHA256 `07e61bdfbc777e43a36902720ef70b295a117953707653dc97060df372bf2c1c`. Reproduce with `python3 -B research/rev7-20260909-codex/stream_csp/verify_witnesses.py` after preserving the existing verification output. It compiles the pinned, hash-checked OFB source and does not rerun the CSP search.

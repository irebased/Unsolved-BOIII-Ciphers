# CrypTool legacy homophonic-100 controls (ASTRA)

Synthetic controls for the finite 4,000-board family in CrypTool's historical Homophone Chiffre. No Rev7 ciphertext or plaintext is read. The source is pinned to `cryptool-org/cto` commit `4fc443f0d87c0e86815695a47ab2d6174c725f82`. PHP was not executed; `controls.py` ports and independently cross-checks the literal array operations. `alfa_dat.php` is ISO-8859 text and must not be transcoded.

The German allocation is `(6,2,3,5,16,2,3,4,7,1,1,3,4,9,3,1,1,7,7,6,4,1,1,1,1,1)`. CrypTool first constructs `00..99`, maps slot `t` to `a*t mod 100`, and rotates that resulting permutation by `b`; because rotation looks each element up in the already permuted array, the final natural-slot formula is `a*(t+b) mod 100`. Controls compare that formula with the literal two-stage construction for all 40 coprime multipliers and all 100 rotations, requiring every board to assign every two-digit code exactly once. Uniqueness is measured over the actual 100-code-to-letter mapping without including `(a,b)` labels; a separate digest binds parameter labels to mapping hashes.

Whole-integer conversion is modeled explicitly: concatenate two-digit codes, convert the decimal integer to uppercase hexadecimal, then invert through a minimal decimal string. Prepending one zero when the recovered decimal digit count is odd restores pair phase. It cannot recover additional leading `00` code pairs; those represent an unknown plaintext prefix, while the decoded suffix remains aligned. Four hex orientations are tested as separate involutions. Decimal digit reversal and decimal pair reversal are not included in this controls package; their inclusion and duplicate structure must be registered before any target grid.

The frozen ranking model uses add-one-smoothed A-Z tetragrams learned only from solved sibling plaintexts rev1–6 and rev8–14. `sibling_tetragrams.json` contains counts, IDs, record lengths, and the source hash; `build_model.py` reproduces it while explicitly excluding Rev7 and forbidding tetragrams across record boundaries. The normal verifier hashes but does not parse the Rev7 record in `revelations.json`. Two new held-out fixed English sequences of 546 and 658 normalized letters use a recorded seeded per-letter phase and cycle through every homophone reachable from their letters. They are passed through decimal-integer/uppercase-hex conversion and recovery, then evaluated against all 4,000 boards. A short choice-zero witness is retained separately. Every future candidate must be retained regardless of score; the score is only an ordering aid and gives no general English exclusion.

Run the read-only verifier from the worktree root:

```sh
python3 -B research/rev7-20260909-codex/homophonic/cryptool100/controls.py
```

Regeneration refuses an existing path:

```sh
python3 -B research/rev7-20260909-codex/homophonic/cryptool100/controls.py --regenerate /tmp/cryptool100-controls.json
```

The ISO-8859 `alfa_dat.php` is also stored exactly as `source/alfa_dat.php.base64` for UTF-8-only transports. The verifier decodes it in memory when the raw file is absent and requires the original 5,376-byte length and SHA-256. To materialize it manually: `base64 -D source/alfa_dat.php.base64 > /tmp/alfa_dat.php` on macOS (`base64 -d` on GNU systems).

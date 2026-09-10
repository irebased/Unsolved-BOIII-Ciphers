# Hexadecimal periodic subtraction and Beaufort follow-up

Identity: ASTRA. Rev7 remains unsolved.

All four relaxed paired-key cases are excluded under the declared 201-codepoint / 165-byte text model. Together they exclude every repeating hexadecimal key of periods 19, 38, or 57 for independent nibble subtraction and Beaufort, after the single fixed AMSCO equal-four-symbol ZOMBIES decode on the forward canonical stream.

| Paired byte period | Nibble decryption | Empty residue masks | Result |
|---:|---|---:|---|
| 19 | (C − K) mod 16 | 19/19 | Excluded |
| 19 | (K − C) mod 16 | 19/19 | Excluded |
| 57 | (C − K) mod 16 | 22/57 | Excluded |
| 57 | (K − C) mod 16 | 26/57 | Excluded |

A repeating m-digit key becomes a paired-byte key with sufficient period m/gcd(m,2). Thus hexadecimal periods 19 and 38 both fit q=19; hexadecimal period 57 fits q=57. For odd periods, the test permits independently chosen paired-byte keys and ignores shared-nibble dependencies. This enlarges the family. An empty residue mask therefore excludes every consistent original key as well.

Each mask enumerates all 256 possible paired key values and intersects those producing a permitted plaintext byte at every observed position in its residue. All indices, observed values, masks and counts are saved. These are exhaustive necessary-condition exclusions for the specified family, not failed language scores. The endpoint covers TAB/LF/CR, printable ASCII, U+00A0–U+00FF, and seven common punctuation codepoints; it does not cover every possible Unicode plaintext.

Controls passed for 131,072 cipher/key/operation pairs and six 546-byte planted messages containing all 201 codepoints. An independent derivation from permitted plaintext bytes checked every candidate-key table. Driver controls restored the AMSCO geometry through a separate index formula and retained every planted true key. Root replayed both control packages. After the single four-cell target run, independent geometry reconstruction and exhaustive slow masks reproduced the complete saved result.

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44/nibble_additive_controls/controls.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44/nibble_additive_controls/independent_arithmetic.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44/nibble_additive_target/driver_controls.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44/nibble_additive_target/run_target.py --verify
```

The frozen target command was `run_target.py --run-target`; it refuses existing result/tmp files. Gate `28223a375fc33d64740a7374389c53a6a764dced09d632bdf6b0278fc0415fdc` pins ten artifacts. FABLE message 407 records the exact scope before execution. Result SHA-256: `fc5be291fc8be6158e32cbcd0f16b49f4bb7c748f2971eaca609eea66d365f7f`.

These exclusions and the [byte-key follow-up](../periodic_followup/RESULTS.md) narrow specific periodic-key explanations of the Kasiski lead. They do not establish the outside program’s Z statistic, settle modern versus classical, or exclude other AMSCO keys, orientations, periods, alphabet orderings, layer placements, or cipher families.

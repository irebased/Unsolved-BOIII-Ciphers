# Periodic-key follow-up after AMSCO 4,4

Identity: ASTRA. Rev7 remains unsolved.

All six registered cases are impossible for the declared 201-codepoint text alphabet. This covers every byte key at periods 19, 38, and 57 for XOR and modular-byte subtraction, after exactly the conventional equal-four-symbol AMSCO decode using ZOMBIES on the forward canonical stream.

| Byte period | Decryption operation | Empty key-residue masks | Result |
|---:|---|---:|---|
| 19 | xor | 19/19 | Excluded |
| 19 | subtract | 19/19 | Excluded |
| 38 | xor | 33/38 | Excluded |
| 38 | subtract | 33/38 | Excluded |
| 57 | xor | 21/57 | Excluded |
| 57 | subtract | 25/57 | Excluded |

For each residue, the test intersects all key-byte values that would map each observed byte into the 165-byte union of the 201 permitted Unicode codepoints. If any residue has no possible key byte, every repeating key is impossible. The result retains every byte index, observed value, 256-bit key mask, and key count; no heuristic score or dictionary is used. The alphabet contains TAB/LF/CR, printable ASCII, U+00A0–U+00FF, and seven common punctuation characters. It is a declared text model, not all Unicode or all possible plaintexts.

The six synthetic controls use 546-byte UTF-8 messages containing every one of the 201 codepoints. All planted keys survived; AMSCO roundtrips were exact, and fast and exhaustive slow masks agreed. Root separately replayed the driver on all six plants. After the single target run, the verifier rebuilt the transformed stream using an independent source-index formula and checked every mask with the slow all-256-keys method; the full result matched.

The adjacent [period proof](../NIBBLE_XOR_PERIOD.md) shows that hex-symbol XOR key periods 19, 38, and 57 are contained in byte-XOR periods 19, 19, and 57. Those nibble-XOR cases are also excluded under the same endpoint. Independent nibble addition/subtraction, other cipher families, layer orders, AMSCO keys, and input orientations are outside this test. The Kasiski program’s Z formula remains unknown.

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44/periodic_followup/controls.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44/periodic_followup/driver_controls.py
python3 -B research/rev7-20260909-codex/coverage/kasiski44/periodic_followup/run_target.py --verify
```

The target command is `run_target.py --run-target`; it refuses an existing result. The verification command above is the intended replay for the published package. Gate `48871ebc6744e7f97038113a7b7a4926990fd3580b6125f2071af65c941c7790` froze the exact six cells and nine dependency files before execution. FABLE message 405 records the plan before the run.

Result SHA-256: `04a478d11641af321bb5dcfb999af4dc067d9e1130663987a39269409f8f23b8`.

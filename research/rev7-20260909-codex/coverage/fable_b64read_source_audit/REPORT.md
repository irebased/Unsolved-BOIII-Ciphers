# FABLE raw-glyph Base64 source audit

Identity: **ASTRA**

## Finding

The captured code does not prove that raw-glyph Base64 is impossible “under any cipher.” It establishes a strong statistical objection under an independent uniform Base64-symbol model, then performs a finite heuristic cipher/key sweep. Every uppercase hexadecimal string is also a syntactically legal Base64 string because `0`–`9` and `A`–`F` are members of the Base64 alphabet. At length 1092, which is divisible by four, the interpretation decodes cleanly to 819 bytes and re-encodes to the identical glyph string. The audit includes two constructive all-hex examples and verifies that property for the canonical displayed string.

The value `(1/4)^1092`, or approximately `10^-657.4`, is exact only for 1092 independent symbols uniformly distributed over the 64-symbol Base64 alphabet. For uniformly random 819-byte strings, the 1092 sextets are jointly uniform because 819 is divisible by three. A fixed cipher/key/input produces one deterministic output, however, and an all-hex Base64 ciphertext can be constructed by choosing legal hexadecimal Base64 symbols and decoding them. The probability calculation is therefore evidence against a pseudorandom-output hypothesis, not a mathematical exclusion of every cipher or construction.

## Captured implementation

`readings.js` lines 15–20 creates five interpretations: four orientations from `cascade_lib.orientations` plus lowercase, and Node decodes each directly as Base64. Its 2,000-row restricted null at lines 52–77 uses `crypto.randomBytes` without a saved seed and generates only one uppercase, displayed-like random interpretation per row. No separately generated lowercase null exists in the captured source or ledger. The stored summary can be inspected, but that exact null cannot be regenerated.

`make_targets.js` lines 26–58 stores five real readings, one independently random all-hex negative, and one Twofish/CFB8/Zombies positive. The positive starts with ordinary plaintext encryption and Base64-encodes the 819-byte ciphertext. Only 280 of its 1092 Base64 symbols are uppercase-hex symbols. The control consequently validates the general Base64 decoding and cipher path; it does not validate recovery when every input glyph is restricted to the hexadecimal subset.

`worker.js` lines 88–107 evaluates 19 block ciphers in four modes and four stream ciphers in their stream mode, giving 80 trials per key per target. It scores bytes after skipping one block for block ciphers and skips zero for stream ciphers. It retains endpoint maxima and 25 UTF-8 hits, rather than every plaintext. `assemble.js` lines 38–49 compares every real and positive reading to the same single stored random-hex negative maximum. This is a heuristic comparator, not a sampled distribution of per-grid maxima.

The stored `out_t0.json`, `out_t1.json`, and `out_t2.json` files contain 3, 280, and 2,338 keys respectively, seven targets each, no reported errors, and exactly **1,467,760** trials in total. The headline **396,081,280** equals:

```
1,467,760 + 704,667 keys × 7 targets × 80 trials/key/target
```

No `out_t3.json` is present in the capture. The arithmetic is internally consistent with an additional 704,667-key tier, but its per-target endpoint results and error counts cannot be verified from these files. Moreover, the captured `run.js` constructs tier 3 from `dictkey/keys_dict.txt`, `keys_lore.txt`, and `keys_artifacts.txt`; `keys_dict.txt` is absent from the mirror. The 396-million headline must therefore be labeled reported/inferred rather than reproduced by this source package.

## Positive replay

The deterministic replay loads the captured mcrypt WebAssembly runtime, Base64-decodes the stored 1092-character positive into 819 bytes, and decrypts it using Twofish, CFB8, key text `Zombies`, and sixteen ASCII `0` IV bytes. It reproduces the exact 819-byte plaintext and re-encrypts to the exact stored ciphertext and Base64 string. The audit also dispatches that stored positive through the captured `worker.js` with the single key `Zombies`. All 80 cipher/mode contexts complete without errors; the Twofish/CFB8/Zombies context is the best UTF-8 hit and recovers the entire 803-byte scored tail after the worker's 16-byte skip. No real target is dispatched.

## Evidence and commands

Captured files, byte lengths, and SHA-256 values are in `audit.json`. The runtime is Node v26.4.0 and the copied `old-ciphers` source commit is `7c43c6ae65f49bd7504494d9ca3c55ce2e2496b6`.

```sh
cd research/rev7-20260909-codex/coverage/fable_b64read_source_audit
node plant_control.js
python3 -B audit.py
```

The Python command verifies every copied source/result/runtime hash, reruns the one positive control, checks the stored tier accounting, checks exact Base64 round trips for the canonical string and constructive all-hex examples, and compares the result to the frozen ledger. It does not rerun the broad target sweep or the nondeterministic null.

## Limits

This audit does not show that the raw-glyph Base64 interpretation is promising. It corrects the logical strength of the existing claim. The finite stored tiers found no compelling endpoint maximum in their declared grid, while the absent tier cannot be independently checked here. Other ciphers, keys, deterministic encodings, and plaintext models remain outside that finite evidence. “Hex” and “Base64” are not unique competing syntactic interpretations for this glyph string: the same 1092 characters are valid under both, yielding 546 and 819 bytes respectively.

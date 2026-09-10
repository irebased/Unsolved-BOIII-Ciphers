# ASTRA lossy-AMSCO `2016` frontier control result

The source-backed geometry check passed: literal legacy key `2016` applied to complete six-hex-character rows preserves natural nibble positions 0, 1, 3, and 4. Reconstructing those nibbles at their natural byte positions produces the exact repeating mask `FF,0F,F0`. The direct oracle equals the pinned CrypTool port at 3, 6, 99, and 819 bytes.

All eight registered A–Z-plus-space plants completed without reaching either safety cap. Every exact planted plaintext/ciphertext path was retained. Each 99-byte cell had one solution and a maximum frontier of 39–63. At 819 bytes, solution counts were 17 for DES/NUL, 1 for DES/ASCII-zero, 16 for AES/NUL, and 1 for AES/ASCII-zero; all additional exact paths are stored in `controls.json`. Maximum frontiers were 45–83 and accepted-state counts were 6,439–7,164. PyCryptodome CFB8 and the manual recurrence agreed.

Four deterministic random 819-byte observations completed with zero solutions; each happened to reject at its first fully observed byte. This is a synthetic control outcome, not a null-rate estimate.

The separately labeled 53-byte-alphabet DES/NUL calibration reached 100,009 frontier states after byte 32 and stopped at the declared 100,000-state cap. It is **incomplete** and makes no exclusion claim. The known planted path remains globally consistent with the complete mask. The heuristic `m^3/65536` is only an ideal-cipher wrong-branch expectation; it is neither a bound nor a guaranteed threshold.

No Rev7 data was read or evaluated. Reproduce the deterministic fields with:

```sh
python3 -B research/char_amsco/astra/lossy2016/controls.py
```

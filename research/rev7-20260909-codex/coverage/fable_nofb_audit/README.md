# ASTRA audit: FABLE full-block OFB controls

This source-and-controls audit does not read or evaluate Rev7 target ciphertext and does not repeat FABLE's target scan.

The mirrored `nofb/lib.js` uses `register = E_key(register)`, then XORs each complete encrypted register block with input and truncates only the final output block. Its ECB helper invokes encryption. Encryption and decryption are the same XOR operation.

The saved corpus contains exactly 180 random comparisons: 60 each for DES with an 8-byte key, Rijndael-128/AES with a 16-byte key, and Blowfish with a 16-byte key. `audit.py` replays every output with PyCryptodome `MODE_OFB` and an independently written ECB recurrence.

The archived divergence ledger records 60 further random trials, 20 per cipher: wrapper mode 4 equaled full-block OFB in all 60 and equaled OFB8 in none. Those random inputs were not retained, so this is archived evidence. Six new deterministic controls use the pinned WASM wrapper. In all six, mode 4 equals independently computed full-block OFB and differs from OFB8 at byte 1.

This establishes the convention for the three registered ciphers only, not every wrapper cipher.

Default verification:

```
python3 -B research/rev7-20260909-codex/coverage/fable_nofb_audit/audit.py
```

Replay the six wrapper controls in a temporary layout:

```
python3 -B research/rev7-20260909-codex/coverage/fable_nofb_audit/audit.py --replay-mode4
```

Regenerate to a new path:

```
python3 -B research/rev7-20260909-codex/coverage/fable_nofb_audit/audit.py --regenerate /tmp/fable_nofb_audit.json
```

The WASM is stored only as pinned Base64 and decoded in a temporary directory. The broken relative path in FABLE's flat private mirror is not repaired or mutated.

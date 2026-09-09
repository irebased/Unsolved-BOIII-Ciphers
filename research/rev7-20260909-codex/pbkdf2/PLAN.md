# Bounded phpseclib-2.0.0 PBKDF2-derived-key probe

Identity: **ASTRA**. This is a planned derived-key experiment. No Rev7 target
cell has been run at this checkpoint.

The immutable phpseclib 2.0.0 tag resolves to commit
`a74aa9efbe61430fcb60157c8e025a48ec8ff604` (2015-08-03/04). Its
`setPassword($password, 'pbkdf2')` defaults are SHA-1, 1,000 iterations, the
class password salt, and the class password key size. The password in this
probe is exactly the seven bytes `b'Zombies'`.

| Cipher | Derived bytes | Salt | Modes |
|---|---:|---|---|
| AES | 16 | `phpseclib` | full-block CFB, OFB, CTR |
| DES | 8 | `phpseclib/salt` | full-block CFB, OFB, CTR |
| TripleDES | 24 | `phpseclib` | full-block CFB, OFB, CTR |
| Blowfish | 56 | `phpseclib/salt` | full-block CFB, OFB, CTR |
| RC4 | 128 | `phpseclib/salt` | plain stream |

Every block mode uses an all-zero block IV. CFB uses the complete block as its
feedback segment, matching phpseclib's `MODE_CFB` implementation rather than
mcrypt CFB8. CTR encrypts the zero counter first and increments the complete
counter as a big-endian integer. OFB feeds each encrypted block back in full.
RC4 uses the ordinary KSA/PRGA stream with no IV and no initial-byte drop.

The target grid is **52 cells**: four canonical Rev7 hex orientations
(`forward`, full symbol `reverse`, `byte_reverse`, and per-byte
`nibble_swap`) × thirteen cipher/mode settings. Each orientation still parses
as exactly 546 bytes. The visible data is treated as ciphertext and each cell
is one recovery/decrypt operation. OFB, CTR, and RC4 are symmetric; duplicate
encrypt labels would add no output. CFB encryption would reverse the data role
and is outside this specific derived-key recovery hypothesis.

CBC and ECB are excluded because unchanged 546-byte framing is not block
aligned (`546 mod 8 = 2`, also `mod 16 = 2`) and this experiment does not add,
guess, or remove padding. Twofish is explicitly omitted because the installed
validated backend does not provide it. Raw or NUL-padded `Zombies` keys and
mcrypt CFB8 belong to FABLE's separate scope and are not duplicated here.

Before target execution, `python3 -B run.py --controls` must pass:

- RFC 6070 PBKDF2-HMAC-SHA1 vectors and byte-for-byte agreement between
  `hashlib.pbkdf2_hmac` and `Crypto.Protocol.KDF.PBKDF2` for every class;
- two-block NIST SP 800-38A AES CFB128, OFB, and CTR known-answer vectors,
  plus the RFC 6229 RC4 offset-zero vector;
- manual ECB-based CFB/OFB/CTR against independent PyCryptodome modes for all
  four block ciphers, including the final partial block;
- complete derived-key plants using a local solved Revelations plaintext for
  every cipher/mode/orientation cell: library encryption, target-row recovery,
  exact library re-encryption, and exact inverse-orientation reconstruction.

If authorized later, `python3 -B run.py --target` will rerun controls first and
abort on failure. It will preserve every complete 546-byte output losslessly as
hex with its exact recipe and SHA-256. The detector evaluates the complete
bytes only: exact allowed-ASCII status (TAB, LF, CR, or bytes 32–126), strict
UTF-8 status, printable-byte fraction, byte IoC, and entropy. It performs no
prefix extraction, error-ignoring decode, padding removal, decompression, or
other lossy endpoint conversion.

Primary source anchors:

- <https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L552-L575>
- <https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L826-L921>
- <https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L1117-L1205>
- <https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L1879-L1905>
- <https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/RC4.php#L251-L335>

Passing controls reproduce the derived-key and mode conventions used here.
Without executing the historical PHP runtime, they do not establish complete
phpseclib wrapper equivalence, engine selection, or a historical Rev7 recipe.

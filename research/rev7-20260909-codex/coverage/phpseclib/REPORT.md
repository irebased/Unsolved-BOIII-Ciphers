# phpseclib primary-source verification

Identity: **ASTRA**. This is source verification only; no Rev7 target scan was run.

The plan’s proposed `phpseclib-php5 1.0.18` is not a pre-2016 release according to its immutable commit metadata: commit `ec1fcfe648e5696efa2dd26ffa54436e3478ae5c` is dated 2019-09-16. The official `phpseclib/phpseclib` tag `2.0.0` is a signed tag object `e9882650bcce57765803480031902db2e2ff3f3a`, pointing to commit `a74aa9efbe61430fcb60157c8e025a48ec8ff604`, tagged 2015-08-04 UTC. It is the verified pre-cutoff source snapshot. Tag and commit URLs are recorded in `verification.json`.

In 2.0.0, `Crypt\\Base::setPassword($password, 'pbkdf2')` defaults to SHA-1 (Base.php lines 560–562), the cipher’s `password_default_salt` (line 564), 1,000 iterations (lines 566–568), and PBKDF2 derived length equal to `password_key_size` (lines 570–575). Base defaults to salt `phpseclib/salt` (lines 388–397). The constructor defaults to CBC (lines 467–485), and the source documents an omitted IV as all-zero bytes (lines 496–500).

The directly declared password key sizes and salts are:

| Cipher | password_key_size | default salt | Source declaration |
|---|---:|---|---|
| Rijndael | 16 bytes | `phpseclib` | Rijndael.php 66–102 |
| AES | inherits Rijndael | `phpseclib` | AES.php declares `extends Rijndael` |
| Twofish | inherits Base = 32 bytes | `phpseclib/salt` | Twofish.php 50–60; Base.php 388 |
| Blowfish | 56 bytes | `phpseclib/salt` | Blowfish.php 50–69 |
| DES | 8 bytes | `phpseclib/salt` | DES.php 54–98 |
| TripleDES | 24 bytes | `phpseclib` | TripleDES.php 49–85 |
| RC4 | 128 bytes (source comment says 1024 bits) | `phpseclib/salt` | RC4.php 56–86 |

These are PBKDF2 defaults for the class’s `setPassword` path. They do not establish a Rev7 historical wrapper, scalar conversion, ciphertext framing, or which key length a hypothetical external tool selected. The plan’s statement that 1.x Rijndael and 2.x defaults must be compared remains directionally useful, but 1.0.18 cannot serve as pre-cutoff provenance without a separate contemporaneous source archive.


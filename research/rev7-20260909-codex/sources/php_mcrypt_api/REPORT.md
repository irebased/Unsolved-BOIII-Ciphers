# PHP mcrypt key-size audit

<!-- identity: ASTRA -->

This is a source audit, not a PHP or libmcrypt runtime test. It uses the exact local snapshots whose hashes are emitted by `audit.py`.

## Result

PHP 5.4.45 `php_mcrypt_do_crypt` queries the algorithm maximum and supported sizes, then allocates a zero-filled key buffer. For the raw 7-byte cases here, `count == 0` keeps the supplied length (Blowfish: 7 bytes). With one supported size, it uses that singleton (DES: 8 bytes). With multiple sizes, it chooses the smallest supported size greater than or equal to the supplied length (Rijndael/AES 7 bytes -> 16 bytes). It copies the supplied bytes and the zero-filled remainder is therefore NUL padding. Source: `php-5.4.45-mcrypt.c:1190-1219`, followed by initialization in the same helper.

PHP 5.6.25 changed this path: `php_mcrypt_is_valid_key_size` accepts only an exact supported size when the module reports a non-empty supported-size list, and `php_mcrypt_do_crypt` returns false on failure before initialization (`php-5.6.25-mcrypt.c:1193-1214`, `:1289-1297`). Thus representative source-transcribed outcomes are:

| Algorithm metadata | PHP 5.4.45 raw 7 | PHP 5.6.25 raw 7 |
|---|---|---|
| Rijndael-128: max 32; supported 16,24,32 | accepted as 16-byte zero-padded key | rejected as unsupported |
| DES: max 8; supported 8 | accepted as 8-byte zero-padded key | rejected as unsupported |
| Blowfish: max 56; supported list empty | accepted as raw 7-byte key | accepted and passed as raw 7-byte key |

The Rijndael metadata is in `rijndael-128.c:418-427`; DES in `des.c:586-595`; Blowfish in the pinned compatibility source `blowfish.c:493-500`.

The 5.6.25 `mcrypt_encrypt` wrapper passes the original `key` and `key_len` into `php_mcrypt_do_crypt` (`:1332-1344`), which then calls `mcrypt_generic_init` with that exact length (`:1312-1316`). Plaintext block zero-padding is a separate operation (`:1299-1310`).

## Provenance and reproduction

Official tagged source URLs: [PHP 5.4.45 mcrypt.c](https://raw.githubusercontent.com/php/php-src/php-5.4.45/ext/mcrypt/mcrypt.c) and [PHP 5.6.25 mcrypt.c](https://raw.githubusercontent.com/php/php-src/php-5.6.25/ext/mcrypt/mcrypt.c). Pinned primary libmcrypt sources at commit `3bd338e2f808e985f5b229a7642d48c26615993f`: [rijndael-128.c](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/rijndael-128.c), [des.c](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/des.c), and [blowfish.c](https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/blowfish.c).

From `/private/tmp/rev7-astra-20260909`:

```sh
shasum -a 256 research/rev7-20260909-codex/sources/php_mcrypt_api/*.c \
  research/rev7-20260909-codex/hex_cfb/native_compat/source/blowfish.c
python3 research/rev7-20260909-codex/sources/php_mcrypt_api/audit.py > /tmp/php_mcrypt_audit.json
```

`audit.py` asserts the frozen source hashes before emitting source hashes, numbered excerpts, and deterministic representative decisions. Its Python decision table is explicitly a transcription of the C branches; it does not identify the PHP/libmcrypt version deployed by any website and does not execute encryption.

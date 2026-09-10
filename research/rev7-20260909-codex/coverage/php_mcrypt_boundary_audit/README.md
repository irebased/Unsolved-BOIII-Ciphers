# PHP mcrypt partial-block boundary audit

Identity: **ASTRA**. This is a source-only audit. It does not read or evaluate the Rev7 ciphertext and runs no cipher experiment.

## Decisive result

The PHP 5.6.25 wrapper does **not** hard-reject non-block-aligned data for block modes. In `php_mcrypt_do_crypt`, it rounds the input length up to the cipher block size, allocates that rounded buffer, zero-fills it, copies the supplied bytes, decrypts the entire rounded buffer, and returns exactly the rounded length. For a 546-byte input this produces 552, 560, or 576 returned bytes for block sizes 8, 16, or 32.

This differs from the captured C/WASM port: its ECB and CBC decrypt branches reject nonaligned lengths, then apply `zero_unpad` only to aligned decryptions. Therefore that port's hard rejection and stripping policy cannot be attributed to historical PHP `mcrypt_decrypt`.

A precise correction to the common shorthand is needed: during decryption PHP zero-extends the **ciphertext before decrypting**. The additional returned plaintext bytes will generally be arbitrary block-decryption output, not necessarily NUL bytes. The PHP wrapper itself does not unpad or trim the returned buffer.

## Primary sources

- PHP 5.6.25 was released at commit [`e37064dae4a80c70405899bb591969bbe6aad9a8`](https://github.com/php/php-src/commit/e37064dae4a80c70405899bb591969bbe6aad9a8), dated 2016-08-18. The unchanged captured file is [`ext/mcrypt/mcrypt.c`](https://github.com/php/php-src/blob/e37064dae4a80c70405899bb591969bbe6aad9a8/ext/mcrypt/mcrypt.c). Lines 1299-1305 implement rounding and zero extension; lines 1320-1325 decrypt and return the rounded buffer.
- The official PHP English manual source at commit [`1d391575445598c99175a17eb012f1c658febaa4`](https://github.com/php/doc-en/commit/1d391575445598c99175a17eb012f1c658febaa4), dated 2014-10-15 and explicitly titled “Update mcrypt_encrypt and mcrypt_decrypt docs for PHP 5.6,” says at lines 45-48 that nonmultiple data is padded with `\0`. This is also shown by the [current official manual](https://www.php.net/manual/en/function.mcrypt-decrypt.php), whose version applicability includes PHP 5.
- The captured 2015 tools4noobs encrypt frontend says it uses PHP `mcrypt_encrypt()` and exposes the relevant mode names. The captured decrypt frontend contains the same `mcrypt_encrypt()` wording, apparently copied. Neither captured HTML file contains the server-side request handler or output formatting logic.

The local C/WASM source is preserved as comparison evidence, not treated as historical PHP source.

## What remains unknown

The tools4noobs server-side PHP handler has not been recovered here. Its frontend does not establish whether it called `mcrypt_decrypt` directly, trimmed returned bytes, rejected lengths before calling PHP, encoded binary output, or performed other postprocessing. Historical PHP behavior is established; exact tools4noobs application behavior remains unverified.

## Reproduction

From the repository root:

```sh
python3 -B research/rev7-20260909-codex/coverage/php_mcrypt_boundary_audit/audit.py
```

To regenerate into a fresh path without overwriting evidence:

```sh
python3 -B research/rev7-20260909-codex/coverage/php_mcrypt_boundary_audit/audit.py --generate /tmp/php-mcrypt-boundary-audit.json
```

The verifier checks every frozen source hash, all cited code/document anchors, the PHP/C-port behavioral distinction, and rounded-length examples. It performs no cryptography.

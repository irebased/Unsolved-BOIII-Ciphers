# RFC 3629 character-AMSCO suffix controls (ASTRA)

This synthetic-only package tests an indexed inverse for the valid-permutation form of the original PHP character AMSCO geometry, followed by ten fixed CFB8 backends. It does not read or evaluate Rev7 and contains no target driver or gate.

`core.py` gathers each ciphertext byte directly from the two natural hex-nibble positions for a proposed column order. The gathered ciphertext prefix is shared across all backends. For block size `b`, bytes from offset `b` onward are decrypted with the IV-independent CFB8 recurrence and passed to an eight-state RFC 3629 DFA. The accepted language is every well-formed Unicode scalar encoding, including ASCII NUL and controls. Surrogates, overlong forms, values above U+10FFFF, malformed continuations, and an incomplete true endpoint are rejected.

An unknown left prefix is represented by `{boundary, remain1, remain2, remain3}`. The special `E0`, `ED`, `F0`, and `F4` states remain restricted inside the observed suffix. Acceptance requires `boundary` at the true end. This is only a necessary UTF-8 condition on the IV-independent suffix; it neither recovers the IV-dependent prefix nor scores language.

## Reproduction

The committed ledger is verified read-only with only the Python standard library:

```sh
python3 -S -B research/char_amsco/astra/utf8_search/controls.py
```

A full synthetic regeneration requires the repository's existing PyCryptodome/OpenSSL toolchain and writes only to a new path:

```sh
python3 -B research/char_amsco/astra/utf8_search/controls.py --regenerate /tmp/astra-utf8-search.json
```

Regeneration refuses an existing output. Before building temporary native libraries, it checks the pinned geometry ledger, cascade control ledger, Rijndael-256 packed control ledger, and every underlying C/header/shim/license hash recorded in `controls.json`. Machine-specific temporary-library hashes are evidence for this run, not portable provenance.

## Control scope

The ledger records exhaustive agreement with Python's strict UTF-8 decoder for all 65,792 strings of length one through two, bounded byte-class products of lengths three through five, and all 1,112,064 Unicode scalars. Geometry covers widths 2 through 9, both starts, and identity/reverse/deterministic orders. Eighty valid plants cover ten backends, four orientations, and two IVs at width 9/start 21; each retains the exact suffix, re-encrypts exactly, and confirms that decrypting one fixed ciphertext under the alternate IV leaves the suffix unchanged. Malformed plants record their first rejection witness, and a separate fixture records terminal truncation.

The registered synthetic benchmark evaluates the first 20,000 lexicographic width-9 orders, start 21, forward orientation, and all ten backends over the prescribed SHA-256-concatenated 546-byte fixture. The timing is a planning measurement only.

The prospective valid-permutation scope is widths 2 through 9, fixed start 21, four orientations, and ten backends: 1,636,448 column orders and 16,364,480 backend contexts. It was not executed here. Repeated-label lossy PHP keys are a separate model.

Primary grammar: [RFC 3629 section 4](https://www.rfc-editor.org/rfc/rfc3629#section-4).

# Encoded endpoint subset audit

Identity: **ASTRA**. This is a target-free set-inclusion audit. It performs no ciphertext search.

The existing 165-byte necessary endpoint bag contains TAB, LF, CR, printable ASCII, UTF-8 continuation bytes, and the lead bytes used by the exact 201-codepoint repertoire. Therefore every byte used by the declared ASCII binary, octal, decimal, uppercase/lowercase hexadecimal, RFC 4648 Base32, and standard Base64 alphabets is already included. The result remains true after adding `=` padding and TAB/LF/CR/space separators. All 18 explicitly enumerated alphabet variants are subsets of bag165 and hence of bag213.

This corrects the claim that the existing hard byte-bag exclusions inherently miss those ASCII-encoded intermediates. If an earlier search applied the bag after decoding the ASCII representation into another binary layer, its placement still matters; this audit proves byte-set inclusion only at the endpoint where the encoded ASCII text is tested.

The common German letters `ä ö ü Ä Ö Ü ß` each encode as `C3 xx`. Every constituent UTF-8 byte is in both bags, and every corresponding codepoint lies in the exact repertoire because it includes U+00A0 through U+00FF. That does not cover all German typography. For example, uppercase `ẞ` (U+1E9E), low German quotation marks `„`/`‚` (U+201E/U+201A), and `€` (U+20AC) are outside the exact 201-codepoint repertoire. Some of their individual UTF-8 bytes may still lie in a necessary byte bag, which is weaker than codepoint acceptance.

Reproduce from the isolated repository root:

```sh
python3 -B research/rev7-20260909-codex/coverage/encoded_endpoint_subset/analyze.py
```

Generation is separate and refuses overwrite:

```sh
python3 -B research/rev7-20260909-codex/coverage/encoded_endpoint_subset/analyze.py --regenerate /tmp/encoded-endpoint-results.json
```

The ledger records every literal alphabet byte, each subset difference, the German UTF-8 bytes and repertoire membership, and source hashes.

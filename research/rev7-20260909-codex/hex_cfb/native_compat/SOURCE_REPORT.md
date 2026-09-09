# Pinned libmcrypt Blowfish compatibility source check

Identity: ASTRA. Target evaluated: false.

## Sources

Pinned repository commit: `3bd338e2f808e985f5b229a7642d48c26615993f` (Distrotech import of libmcrypt 2.5.8, 2013-01-27).

- Standard source: https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/blowfish.c
  - Git blob SHA: `ee7d885ef20f24f704b435294cad01322a364c79`
  - Preserved-file SHA-256: `c384305eb4f5d7134e60f6deaed92bba94757826da4b8d35de8326422c286736`
- Compatibility source: https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/blowfish-compat.c
  - Git blob SHA: `b69fd3f7c19d954f904ea1bba85b4a0856102a4d`
  - Preserved-file SHA-256: `3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad`
- Shared header: https://github.com/Distrotech/libmcrypt/blob/3bd338e2f808e985f5b229a7642d48c26615993f/modules/algorithms/blowfish.h

The upstream files are preserved unchanged under `source/`. Their header notices place modifications under the libmcrypt license; the pinned license text is preserved as `source/COPYING.LIB`.

## Key setup

The standard source initializes the schedule at lines 422-473 and passes `k,len` unchanged at lines 475-478. Its P-box loop at lines 441-450 consumes four bytes big-endian and indexes every byte modulo `keybytes`.

The compatibility source uses the same initialization structure. Its P-box loop at lines 533-542 is identical, and lines 567-570 likewise pass `k,len` unchanged. Both then expand P and S entries with the same internal `enblf_noswap` rounds.

Therefore the compatibility relationship is not a 16-byte-key special case. For every positive supported key length, including the raw seven bytes of `Zombies`, both variants build the same schedule from the same bytes and length. Short keys are cycled by modulo length; neither source pads them with NUL bytes.

## Block byte order

The standard external encrypt function at lines 36-72 interprets each input word in standard Blowfish byte order: on little-endian hosts it applies `byteswap32` on load and store.

The compatibility function at lines 43-79 uses the opposite preprocessor condition: on little-endian hosts it loads and stores native words directly; on big-endian hosts it applies `byteswap32`.

The rounds between those loads and stores are identical. Thus, on either host endianness:

```text
BF-compat(key, block) =
    word_reverse(BF-standard(key, word_reverse(block)))
```

Here `word_reverse` reverses bytes inside each 4-byte half and preserves the order of the two halves.

## Direct raw-seven-byte source confirmation

Both preserved C sources were compiled unchanged with minimal ABI headers. Three fixed blocks were encrypted with exact key hex `5a6f6d62696573` (`Zombies`, seven bytes). For every row, the actual compatibility source equaled the word-reversal composition of the actual standard source and the existing OpenSSL adapter.

| Input block | BF-compat output |
|---|---|
| `0001020304050607` | `b24067da92018993` |
| `3030303030303030` | `ba4e4c46586fbdc0` |
| `83b57b2c3434697f` | `7b049752cda58f6f` |

The third block is the known first eight Rev7 bytes supplied in the task context. This source check did not read the Rev7 file and ran no Rev7 decryption or search.

Machine-readable frozen check: `source_check.json`, SHA-256 `4b415587e87d629f2486c8992b2b3f4e7ee0eb0cc01d9931d8d9a4cddedaf829`. Reproduction source: `source_check.py`; it refuses to overwrite that ledger by default.

This establishes the raw-seven-byte block adapter directly from pinned libmcrypt source. It remains independent of the pending direct `Zombies` WASM fixture and does not establish any historical frontend key preprocessing before libmcrypt receives `k,len`.

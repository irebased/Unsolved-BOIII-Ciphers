# libmcrypt mode classification and RA codec scope

Identity: **ASTRA**. The audit.py program checks frozen source and finite witness models. The companion runtime_witnesses.py records actual RA CLI checks on synthetic inputs. Neither uses Rev7 ciphertext or performs a target search.

## libmcrypt 2.5.8 mode classification

The frozen source is the Distrotech mirror of libmcrypt 2.5.8 at commit `3bd338e2f808e985f5b229a7642d48c26615993f`. `configure.in` declares version 2.5.8. `modules/modes/Makefile.am` lists exactly eight mode modules in that source tree: OFB, CTR, CFB, nCFB, nOFB, ECB, CBC, and STREAM.

`mcrypt_enc_is_block_mode(td)` in `lib/mcrypt_modules.c` resolves `_is_block_mode` from the selected mode handle with `mcrypt_dlsym`, then directly returns that callback's value. The complete source inventory is:

| mode | callback | source line |
|---|---:|---:|
| ECB | 1 | `ecb.c:82` |
| CBC | 1 | `cbc.c:159` |
| CFB | 0 | `cfb.c:155` |
| CTR | 0 | `ctr.c:233` |
| nCFB | 0 | `ncfb.c:314` |
| OFB | 0 | `ofb.c:157` |
| nOFB | 0 | `nofb.c:212` |
| STREAM | 0 | `stream.c:68` |

Consequently, PHP 5.6's block-mode rounding branch applies to ECB and CBC. It does not apply to the six feedback/counter/stream modules.

CTR is an actual module in this pinned libmcrypt 2.5.8 tree. The separately captured WASM wrapper also contains a mode numbered CTR, implemented locally. This source audit establishes the upstream module's existence; it does not assert that the wrapper's custom CTR recurrence is identical to upstream libmcrypt CTR.

Primary source: [Distrotech/libmcrypt at the pinned commit](https://github.com/Distrotech/libmcrypt/tree/3bd338e2f808e985f5b229a7642d48c26615993f).

## Pinned RA codec semantics

The codec files are frozen from RA commit `e127b8d6c17f567b930fe67624d3ea199528b775`. Their bytes also match ancestor commit `e6c282187cc8a555580349d819210b544e5417b1`.

- **Base64:** retains only ASCII alphanumeric bytes plus `+`, `/`, and `=`; silently discards every other byte; appends `=` until the retained length is divisible by four; then asks base64 0.22.1's `STANDARD` engine to decode. Invalid placement or structure may still fail.
- **Hex:** retains only ASCII hexadecimal digits, silently discards other bytes, drops the last retained nibble when the retained count is odd, then decodes.
- **Decimal:** first requires the entire buffer to be valid UTF-8, splits only on ASCII whitespace, requires at least one token, and parses every complete token as a base-10 `u8`. It does not impose three-digit width.

A clean unpadded 546-character Base64 string has residue 2 modulo 4. RA appends two `=` characters and decodes it to 409 bytes. Therefore “546 cannot be Base64” is false for this implementation. The audit also checks valid-UTF-8 non-ASCII witnesses whose bytes are discarded by Base64/hex, and a non-ASCII-space decimal witness which is rejected.

Padding a prior ciphertext to 552 or 560 bytes changes the byte sequence as well as its length. Those lengths are divisible by four, but divisibility alone does not establish Base64 syntax, decoder acceptance, or meaningful decoded content. Conversely, 546 alone is not a rejection condition.

The distinct-byte occupancy bound for strict small alphabets does not automatically cover these permissive RA Base64/hex decoders: they can discard out-of-alphabet bytes. Decimal remains an all-input syntax check under the rules above.

## Reproduction

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/coverage/libmcrypt_mode_codec_scope/audit.py
```

Regenerate to a new path:

```sh
python3 -B research/rev7-20260909-codex/coverage/libmcrypt_mode_codec_scope/audit.py --generate /tmp/libmcrypt-mode-codec-audit.json
```

The default verifier pins all source bytes, the complete mode-module list, callback trace and values, RA source and dependency versions, and compact codec witnesses.

## Root verification and actual executable witnesses

Root ran `audit.py` successfully, then ran `runtime_witnesses.py --run-record` against the previously built private RA executable from the published first-layer inventory. The retained ledger contains twelve actual CLI invocations, exact inputs, commands, return codes, stdout/stderr and decoded output bytes. A later default invocation verified that receipt without executing RA again. The binary SHA-256 is `7908ab34a2f396f6084c56e1c8066eb5400df7498ee0f0ebdee88c3d52f899b1`; its frozen source archive and instrumentation patch are published in the sibling `ra_prefix_inventory` directory at commit `de4c56a57365325c802ceaafa604fbc62b123ebd`.

The actual CLI uses `--display bytes` and appends `hexencode` to each decoder chain. This preserves output bytes when capturing the CLI's otherwise lossy UTF-8 display. Actual 546-byte decimal and octal inputs (`b"0 " * 272 + b"00"`) both decode to 273 zero bytes. No fixed three-digit field requirement exists.

The Python functions in `audit.py` are **finite witness models, not equivalent implementations of the entire Rust parsers**. Two actual CLI cases make that distinction explicit: Rust rejects Base64 `AB` for noncanonical unused trailing bits, while Python's `base64.b64decode(..., validate=True)` accepts it; Rust accepts decimal `+1`, while the limited Python digit-only witness model rejects it. None of the original selected witness results changes. The actual receipts, not those models, establish these edge cases.

Execution note: an initial twelve-case batch completed but its receipt validation incorrectly required the word `node` in rejection messages. RA actually reports `Error: b64decode: ...`. Root inspected that exact error and corrected the message assertion before repeating the small synthetic batch and retaining its receipt. Two separate one-case probes established CLI output and error formatting. No target search was run or repeated.

The actual current sweep also uses these decoders. `current_source_receipt.json` records files extracted with `git show 25958812bb28d610bbdb971a479bc99067b9c907:<path>` from the read-only FABLE checkout. Its `sweep.rs:1252-1266` dispatches `Codec::apply` to the same `ra_core::repr` functions used by the CLI nodes. Current `repr.rs` is byte-identical to the pinned e127b8d version. Full current source files are included. This source check ties the decoder witnesses to that dispatch; it does not claim execution of the current sweep binary.

```sh
python3 -B research/rev7-20260909-codex/coverage/libmcrypt_mode_codec_scope/runtime_witnesses.py
```

The default verifies the retained receipt. `--run-record` is reserved for fresh reproduction and refuses to overwrite an existing receipt.

The companion `ra_padded_tail_occupancy_bound/scope_review.md` independently reviews the old/new ECB/CBC code. The first 544 plaintext bytes remain identical under identical parameters because 544 is divisible by 8, 16 and 32. Exact new lengths 552/560/576 are already inside the published bound's intervals. The review preserves the scope of the 3,312 saved READY labels and does not infer a historical site backend.

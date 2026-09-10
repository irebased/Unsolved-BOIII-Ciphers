# ASTRA raw-glyph Base64 history audit

This source-only audit asks whether ASTRA previously removed whitespace from the 1,092 displayed Rev7 hexadecimal glyphs and fed those literal ASCII glyphs directly to a standard Base64 decoder, producing 819 bytes. It did not decode or otherwise evaluate Rev7.

## Finding

No exact execution of that route was found in the reviewed ASTRA Python/JavaScript source and saved bus records. This is a bounded statement about the pinned local corpus, not proof that nobody has tried it elsewhere.

The closest prior lane is materially different. `hex_cfb/native/run_target.py` interprets pairs of displayed glyphs through a global hexadecimal-symbol bijection, decrypts the resulting 546 ciphertext bytes with CFB8, and tests whether the plaintext bytes belong to a permissive 69-byte Base64-plus-whitespace alphabet. Its completed result covers three ciphers and four orientations: 12 exhaustive membership cells, zero survivors. It never Base64-decodes the literal displayed glyph string. The saved announcement explicitly says this endpoint is “permissive alphabet membership, not a Base64 grammar test.”

A second superficially similar count is also unrelated. `char_amsco/astra/lossy2016/target/run_target.py` searches a natural 819-byte ciphertext whose hexadecimal emission was reduced to 1,092 observed glyphs by a source-derived lossy AMSCO model. The number 819 is that model’s inferred pre-loss ciphertext length; the 1,092 glyphs are not decoded as Base64.

The audit inventories every textual Base64 decode-call match in `research/**/*.py` and `research/**/*.js`, excluding dependency, SMT, drafts, and this audit. Matches include quoted code and metadata as well as executable calls; each is classified as artifact/source packaging, solver/result transport, a solved-sibling full-buffer control, or a synthetic alignment control. None consumes the literal Rev7 glyph sequence. Archive transport Base64 is not a cipher hypothesis.

The cached public evidence is a recursive Git **tree** response with tree SHA `922d67269571bf13a69c887a933c8edaf321c354`; the audit records blob IDs and sizes for the relevant published sources. That response does not identify its containing commit, so the report does not invent one.

## Minimum controls for a future source review

A direct implementation should:

1. Pin the exact whitespace-stripped 1,092-glyph input and its image/data/source hashes.
2. Declare standard Base64 case, padding, and whitespace rules; assert all glyphs are in that alphabet and the length is divisible by four.
3. Strict-decode once, require 819 bytes, retain the complete binary result/hash, and require exact standard Base64 re-encoding to the original glyphs.
4. Include a synthetic binary roundtrip plus invalid padding/corruption controls.
5. Treat the 819 decoded bytes as binary. Any later cipher, compression, parser, or language claim needs a separately defined model and inverse checks.

The arithmetic `1092 / 4 * 3 = 819` is recorded without performing the target decode.

## Reproduction

```sh
python3 -B research/rev7-20260909-codex/coverage/raw_glyph_base64_history_audit/audit.py
```

This verifies all pinned sources, reconstructs the frozen decode-call text-match inventory, checks the 12-cell prior result accounting, and compares the complete saved audit ledger.

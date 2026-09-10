# Lossy-four-map exact UTF-8 endpoint controls

Identity: **ASTRA**

This synthetic package extends the all-IV DES suffix frontier from printable ASCII to the exact 201-codepoint endpoint frozen in `coverage/transposition_byte_bag/proof.py`: TAB, LF, CR, ASCII U+0020..U+007E, Latin-1 U+00A0..U+00FF, and seven registered punctuation codepoints.

The automaton carries a set of possible codeword-prefix states because plaintext byte 8 may begin inside a two- or three-byte UTF-8 codeword. It starts with the boundary plus every proper-prefix state. A terminal suffix is valid when the boundary state is present; another unfinished alternative does not invalidate that completed existential context. The single byte `80` is the explicit control: its ending set contains both boundary and `after-E2-80`, and prefix `C3` completes an allowed Latin-1 character. Each ciphertext/plaintext path carries one determinized state set, preventing duplicate paths from multiple initial contexts.

Transitions encode full codewords. They never accept all 165 endpoint bytes independently. All 201 codewords and every byte string of length zero through two are compared with an independent strict UTF-8 plus allowed-codepoint prefix-completion oracle. Invalid ordering, leads, continuations, truncation, and an all-bytes-in-union counterexample are included.

Crypto controls use both dynamic root shapes across two 99-byte and two 655-byte plants. Byte 8 begins inside a two- or three-byte codepoint in every plant. Full plants include TAB/LF/CR, all seven punctuation codepoints, and every registered Latin-1 codepoint. Every terminal completion is checked with PyCryptodome suffix CFB8, a separate manual recurrence, the independent Unicode oracle, hashes, lengths, and literal source emission. A capped positive is INCOMPLETE and has no truth-retained claim. Two deterministic nulls and both cap shapes are also checked.

The raw ledger is 41,519,030 bytes; the lossless zlib/base64 transport is 2,384,656 bytes. The transport verifier decompresses with a strict output bound, rechecks all 65,793 small oracle cases, and revalidates all 13,796 retained terminal candidates without rerunning the frontier.

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/pack_controls.py
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/pack_controls.py --unpack /tmp/lossy4-utf8-controls.json
python3 -B research/rev7-20260909-codex/lossy4_utf8_controls/controls.py --regenerate /tmp/recomputed.json
```

No Rev7 data is read and no target driver or gate is present.

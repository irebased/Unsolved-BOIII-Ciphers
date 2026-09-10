# Loki97 key-buffer history probe

Identity: ASTRA. This synthetic probe reads no Rev7 data. It uses the actual FABLE-mirrored WASM with a fixed 64-byte input `00..3f`, a zero IV, CFB8, and the seven-byte key `Zombies`.

- A: clear the key buffer, write the short key, decrypt.
- B: perform a call with a 32-byte key `a0..bf`, then write the short key without clearing the unused tail and decrypt the same input.
- C: clear the key buffer and repeat A.
- D: clear the buffer, write the same short key, change only byte 31 to `5a`, and decrypt.

A and C match. B and D each differ from C. Root reran the reviewed source and reproduced the complete JSON byte for byte, SHA-256 `a115b77693cae20c7365750cf45634a0bc167d17711325236e2b7a923c4673ec`. The harness copies every output and backing-key snapshot before the shared buffer is reused.

```sh
node research/rev7-20260909-codex/loki97_key_tail/key_tail_probe.js
```

The harness expects FABLE's mirror at `/private/tmp/rev7-fable-20260909/old-ciphers/`. It checks the WASM SHA-256 `60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7` and the included Loki97 source hash before loading. Root separately checked the loader SHA-256 `8998b6dd50ebc24aede3df84228826951f2143fde393e15f95d1455e074d5061`; the harness does not pin the loader itself. Script SHA-256 is `7a0e72a7587bb988df0cb97ff67906661f3ba5620d0732c921167a701b460c1c`.

In the mirrored wrapper, `pad_key_16_24_32` clears only bytes 7 through 15 for this short key. The Loki97 primitive source reads eight 32-bit words regardless of its declared key-length argument (`iv_independent/cascade/runtime/source/loki97/loki97.c`, lines 220–251). A caller that writes only the short key without clearing the remaining backing bytes can therefore inherit key material from an earlier call. Repeated identical short-key calls do not test that history effect.

The result establishes this mechanism in the tested runtime. It does not establish that every historical FABLE hit mismatch has this cause, and it does not correct or rerun any dictionary scan. Full source and result bytes were shared with FABLE in message 163. A deterministic zero-tail reference must clear the complete backing buffer before each call and state the intended key-size convention.

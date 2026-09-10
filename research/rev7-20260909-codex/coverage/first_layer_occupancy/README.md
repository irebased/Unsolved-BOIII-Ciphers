# Direct first-layer WASM occupancy pass (prepared, not run)

Identity: ASTRA. Status: synthetic controls complete; target driver inert. Target evaluated: false.

This package prepares one direct first-layer pass through the pinned historical-cipher WASM wrapper. The keys are literal seven-byte ASCII Zombies and ZOMBIES. Every call clears the complete 256-byte shared key buffer first. All ciphers receive the literal seven bytes except Loki97, whose convention is an explicit 32-byte zero backing buffer with the literal copied into bytes 0 through 6.

The block mode codes are CFB8 0, NCFB 3, OFB 4, and CTR 5. Each block context uses an all-zero IV and an ASCII-0 (0x30) IV of the exact block size. Stream ciphers use their actual three-argument API without mode or IV duplication.

The five orientations are forward hex; reversal of all 1,092 hex glyphs; reversal of 546 byte pairs; nibble swap within every byte; and reversal of the 219 visible source tokens while preserving token interiors (G).

The finite grid has 19*4*2*2*5 = 1,520 block decryptions and 4*2*5 = 40 stream decryptions, totaling 1,560. Block outputs are scored on the complete returned buffer and the tail after one native block. Streams are scored only on the complete buffer: 3,080 windows if all calls succeed. Outputs are never cropped or padded. Every context retains its descriptor, output length/hash and occupancy results; flagged rows also retain complete output hex. Errors remain explicit.

The frozen occupancy table flags D values whose exact independent-uniform-byte occupancy tail is at most 1e-15 for that length. Flagged means retain for inspection, not cipher exclusion or plaintext.

## Synthetic actual-path controls

controls.js encrypts and decrypts a 546-byte plant over 40 non-ASCII byte values (80..A7 hex) through all 312 base contexts: 304 block contexts and eight stream contexts. Every recovery is byte exact; every full output has D=40, as does each block-skipped tail. The ledger records all context and output hashes, key lengths, mode/IV labels, scorer results, and clear counts.

Stream WASM functions return no length, so runtime.js uses the supplied length after the call, matching the pinned helper. Wake uses encrypt direction 1 and decrypt direction 0; the others are symmetric but use the same pair. The controls caught the initial mistaken use of the undefined stream return.

Default target-free commands:

    node research/rev7-20260909-codex/coverage/first_layer_occupancy/controls.js
    node research/rev7-20260909-codex/coverage/first_layer_occupancy/run_target.js

Explicit control generation refuses an existing path:

    node research/rev7-20260909-codex/coverage/first_layer_occupancy/controls.js --generate /tmp/first-layer-controls.json

Prepared target command, requiring later public registration and root GO:

    node research/rev7-20260909-codex/coverage/first_layer_occupancy/run_target.js --run-target

The driver refuses an existing result or temporary file before reading canonical sources. Default preflight hashes all runtime/WASM/scorer/control dependencies and reruns synthetic controls without reading or hashing canonical target bytes.

## Limits

This tests one fixed direct layer only. It does not search keys, encodings, second layers, padding, more IVs, or alternate mode semantics. A one-block tail is an inspection view, not an all-IV proof for every mode. No target result exists.

# Global hex substitution over fixed XOR keystreams (ASTRA)

This package tests a global bijection of the 16 displayed hex symbols before decryption by a fixed, plaintext-independent XOR keystream. For displayed symbols `a,b`, a bijection `g`, and keystream byte `K[i]`, the model is

```text
P[i] = ((g(a) << 4) | g(b)) XOR K[i].
```

The endpoint is exactly 98 single-byte values: TAB, LF, CR, and bytes 32 through 126. It is not a UTF-8 model.

## Certified bounds

For displayed high symbol `a`, `W[a][v]` counts positions where assigning `g(a)=v` makes the plaintext high nibble one of `{0,2,3,4,5,6,7}`. Every allowed ASCII byte has one of those high nibbles. Therefore every bijection satisfies

```text
ASCII_count <= sum_a max_v W[a][v].
```

The saved 16 by 16 matrix and row maxima are a directly replayable certificate. An upper bound below `ceil(0.75*N)` conclusively excludes plaintexts with at least 75 percent bytes in the endpoint. An upper bound at or above the threshold remains unresolved.

When the high bound is weak, the implementation computes a tighter ordered-pair-class relaxation. It maximizes each displayed pair class independently while enforcing `x=y` exactly when its two displayed symbols are equal. This remains an upper bound because it drops consistency between classes. If and only if that relaxation permits every position, a finite all-different CSP decides whether a fully endpoint-valid mapping exists. This CSP decides the 100-percent endpoint question; it does not solve the weighted 75-percent problem.

## Controlled runtime scope

The controls test the identity `D(C)=C XOR D(0)` using zero and two independent 546-byte messages. All 19 registered block primitives pass in modes OFB (mode code 4) and CTR (mode code 5), for both literal keys and both IVs. Panama and Arcfour pass the same three-message test for each key. Enigma and WAKE fail and are excluded. OFB and CTR are source-supported fixed-keystream constructions in the captured wrapper/mode sources. The underlying Panama and Arcfour algorithm C sources were not captured, so their 20 future cells are an empirically controlled conditional model, not a universal source proof.

The inert target scope is 780 cells:

- 760 source-supported block cells: 19 primitives x 2 modes x 2 keys x 2 IVs x 5 orientations.
- 20 empirically supported stream cells: Panama/Arcfour x 2 keys x 5 orientations.

Keys are the literal ASCII strings `Zombies` and `ZOMBIES`. IVs are all-zero bytes and ASCII `0` bytes of the primitive block size. Orientations are forward, full hex-character reversal, byte-pair reversal, nibble swap, and reversal of the visible 2/5-character image-token order. Every result row retains the complete keystream, high-nibble matrix, and any tighter certificate or full-ASCII witness.

Some raw-`Zombies`, full-block-OFB cells overlap earlier `stream_csp` and `stream_csp_compat` work. The result records exact keystream/display hash matches to those ledgers. The new quantitative 75-percent bound and the broader CTR/key/orientation/runtime grid are distinct; overlap is not counted as a new strict-endpoint exclusion.

## Limits

A certified negative applies only to this global 16-symbol bijection, the stated fixed keystream, and the 98-byte endpoint. It does not cover CFB/nCFB feedback, changing mappings, UTF-8 or other encodings, other keys/IVs, or transformations inserted between the mapped ciphertext and XOR layer. Panama/Arcfour conclusions remain conditional on the controlled fixed-keystream behavior.

## Commands

Synthetic controls and source pins:

```sh
node research/rev7-20260909-codex/coverage/hex_substitution_keystream/controls.js
```

Target-free preflight:

```sh
node research/rev7-20260909-codex/coverage/hex_substitution_keystream/run_target.js
```

The target command remains blocked until a separately reviewed gate grants it:

```sh
node research/rev7-20260909-codex/coverage/hex_substitution_keystream/run_target.js --run-target
```

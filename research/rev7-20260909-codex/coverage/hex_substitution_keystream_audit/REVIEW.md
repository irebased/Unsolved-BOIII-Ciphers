# Fixed-keystream hex-substitution audit

Identity: **ASTRA**. This is a mathematical and source audit. It does not read or evaluate the Rev7 target.

## Conclusion

The claim that a global hexadecimal-symbol substitution has “no gradient” before a known-key decrypt is false for a fixed XOR keystream. Let the displayed high/low symbols at byte position `i` be `(a_i,b_i)`, let `g` be a permutation of `0..15`, and let `K_i` be fixed independently of the transformed ciphertext. Then

```
P_i = ((16*g(a_i) + g(b_i)) XOR K_i).
```

Every proposed `g` therefore has an exact bytewise score. More usefully, a cheap relaxation gives a certified upper bound without enumerating `16!` maps.

Partition positions by ordered displayed-symbol pair `(a,b)`. For that class define

```
W_ab(x,y) = number of its positions whose ((16*x+y) XOR K_i) is allowed,
```

where `x=y` iff `a=b`. Then

```
max over global bijections g of allowed positions
    <= sum over (a,b) of max_(locally legal x,y) W_ab(x,y).
```

This is sound because every global bijection chooses one locally legal pair `(g(a),g(b))` in each class. The relaxation merely lets different classes make mutually inconsistent choices. Dividing by `N` gives an upper bound on the maximum allowed-byte fraction. If it is below `ceil(0.75*N)/N`, no map can reach a 75% ASCII threshold. The target-free reduced-alphabet controls exhaust every permutation in 64 deterministic cases and confirm the exact maximum never exceeds this pair-class bound.

A second, usually weaker assignment bound groups by high symbol. For each proposed `g(a)=x`, it lets every occurrence choose its low image optimistically (except `a=b`, where it must use `x`). Summing each high-symbol row maximum gives the simplest bound; a `16x16` maximum-weight bijective assignment is a tighter upper bound. Taking the smaller of independently sound upper bounds remains sound.

If the pair-class bound equals `N`, intersecting every class's all-positions-valid `(x,y)` relation and solving the 16-variable all-different CSP decides **100% bytewise membership** exactly. It does not by itself decide whether some mapping reaches 75%; that requires a weighted MaxCSP/branch-and-bound or a sufficient upper-bound rejection.

## Eligible mode boundary

The pinned wrapper source proves full-block OFB and CTR are XOR keystream modes whose state depends only on the key and IV. OFB updates its register only by block encryption and XORs the result into data (`mcrypt_wrapper.c` lines 332–345). CTR encrypts an IV-derived counter and XORs it into data (`347–366`). Dispatch codes 4 and 5 select those macros (`404–409`). These contexts satisfy the equation exactly.

CFB8 and full-block CFB are outside this proof: their later registers incorporate ciphertext, so changing `g` changes later keystream bytes. CBC and ECB are also nonlinear block transforms of the substituted bytes.

The wrapper calls all four stream algorithms without a mode or IV (`first_layer_occupancy/runtime.js` lines 34–46), but that API classification does not prove fixed XOR behavior. The captured C wrapper uses the same encrypt routine for RC4, Enigma and Panama, while WAKE has distinct encrypt/decrypt calls (`mcrypt_wrapper.c` lines 589–625). Three deterministic full-length probes found the XOR identity for Panama and Arcfour, and concrete failures for Enigma at byte 1 and WAKE at byte 4 under both fixed keys. The passing Panama/Arcfour rows are empirical evidence; a source proof or a control that binds the actual implementation is still preferable. A bounded search of the captured repository, its complete Git object list, the ASTRA source archives, `/private/tmp/ra-prefix-fix`, and the FABLE mirror found no `panama.c` or `arcfour.c`. The pinned build script names `/tmp/libmcrypt/modules/algorithms/{panama,arcfour}.c`, but that build-time directory is absent; only the wrapper, an Arcfour state-layout header, and the compiled WASM remain. Consequently no source-level proof for those two implementations is available from the capture. Enigma and WAKE must not enter a fixed-keystream certificate.

## Existing coverage and incremental scope

`stream_csp/RESULTS.md` records a prior exact `16!` global-hex-map search for AES128, DES and Blowfish, historical OFB8 and full-block OFB, three IVs and four orientations under `Zombies`: all 72 cells closed. Its independent witnesses even exclude arbitrary byte maps in 68 cells. `stream_robustness/REPORT.md` records 96 related fixed-stream contexts and allowed-byte minima, including the compatibility primitive.

A new package should compare actual keystream hashes and mark those cells as prior coverage. Incremental candidates include the other block primitives in wrapper OFB/CTR, `ZOMBIES`, the G orientation, and source-justified fixed-XOR stream implementations. It should not present the old 72 cells as new work.

## Endpoint limits

For strict UTF-8, bytewise membership in the accepted 213-byte bag is a necessary relaxation: if its upper bound is below the required count, strict UTF-8 is impossible. Passing the bag bound does not establish sequence validity. Exact strict UTF-8 feasibility can be expressed with the same 16 permutation variables plus a small DFA state chain over 546 bytes, or checked at complete CSP mappings. Runtime and formula size are not measured here. Restricted ASCII encodings are especially cheap because their byte alphabets are subsets of the ASCII set.

The result covers substitutions immediately before a fixed XOR-keystream layer with fixed alignment and length. It does not cover feedback modes, insertions, deletions, per-position maps, unknown keys/IVs, or deeper layers whose first undone transform is feedback-dependent.

## Reproduction and pins

From `/private/tmp/rev7-astra-20260909`:

```
python3 -B research/rev7-20260909-codex/coverage/hex_substitution_keystream_audit/bound_reference.py
node research/rev7-20260909-codex/coverage/hex_substitution_keystream_audit/stream_probe.js
```

Pinned evidence:

- captured old-ciphers build script (documents the absent `/tmp/libmcrypt` inputs): SHA-256 `5487af4bb11c72be58a557a826ce6a937bc8bed3cd4a0b36d717c1d43b1851e9` at captured commit `7c43c6ae65f49bd7504494d9ca3c55ce2e2496b6`
- captured wrapper: `research/rev7-20260909-codex/coverage/ra_partial_block_inventory_audit/source/mcrypt_wrapper.c`, SHA-256 `ae134769f33ea4f6f1e42599706d7050670ad33669ce9c8c3fc22d1496f38982`
- frozen runtime: `research/rev7-20260909-codex/coverage/first_layer_occupancy/runtime.js`, whose embedded pins bind the JS/WASM runtime
- bound controls: `bound_controls.json`, SHA-256 `615a93e3d2380415b79ab474064b925f7d8e0e4ba1ee41201dc0a7a8893b1fc9`
- stream probes: `stream_probe.json`, SHA-256 `100dcea5baf976e7a7ced649c17dd24cca9b451e5689729ea1ce3f43857ba1a0`

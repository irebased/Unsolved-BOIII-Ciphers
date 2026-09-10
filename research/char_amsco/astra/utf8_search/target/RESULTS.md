# RFC 3629 character-AMSCO target result (ASTRA)

The registered search completed all 32 cells. It examined exactly 1,636,448 valid-permutation character-AMSCO column orders and 16,364,480 fixed-backend CFB8 contexts. Every context failed the complete RFC 3629 suffix condition. There were zero retained contexts and zero unexamined orders or contexts.

## Exact scope

The search used widths 2 through 9, fixed alternating start 21, four canonical hex orientations, and these ten controlled backends: AES-128, DES, Blowfish, Blowfish-compat, RC2 with effective key length 1024, Twofish, Loki97, and Rijndael-256 with 16-, 24-, and 32-byte keys. Key, block, and source conventions are those frozen by the synthetic control ledger.

Each inverse character-AMSCO order gathered byte pairs directly from natural nibble positions. For each backend, CFB8 plaintext became IV-independent after its block-size prefix. The endpoint accepted any RFC 3629 Unicode scalar sequence, including ASCII NUL and controls. The left-cut initial states were boundary/remain1/remain2/remain3; the true endpoint required boundary.

The result is a finite exclusion of this exact valid-permutation, fixed-start, fixed-key/backend model under the necessary UTF-8 suffix condition. It does not cover repeated-label lossy PHP keys, other starts, widths, keys, cipher conventions, modes, framing, or the unknown IV-dependent prefix. UTF-8 validity is a byte condition rather than English scoring.

## Accounting

- Cells: 32 complete, uncapped
- Orders: 1,636,448 examined; 0 unexamined
- Backend contexts: 16,364,480 examined; 0 unexamined
- Rejected: 16,364,480
- Retained: 0
- Block callbacks: 56,740,112
- Gathered ciphertext bytes: 60,583,902
- Sum of recorded cell search times: 318.394 seconds
- Width-9 cell times: 67.005, 71.933, 71.662, and 70.714 seconds

First-witness reason totals were 158,763 E0 lower-bound failures, 159,136 ED surrogate-guard failures, 147,620 F0 lower-bound failures, 171,021 F4 maximum-scalar failures, 1,077,327 invalid high leads, 8,185,339 missing or invalid continuations, 196,241 overlong leads, and 6,269,033 stray continuations. These sum to all 16,364,480 rejected contexts.

Each cell stores complete factorial/context accounting, hashes of every canonical order row and every first-witness row, reason counts, and its first and last lexicographic rows. No survivors existed to invoke the registered full geometry, two-IV, and re-encryption replay path.

## Reproduction and verification

The single authorized command was:

```sh
python3 -B research/char_amsco/astra/utf8_search/target/run_target.py --run-target
```

Portable read-only verification requires only the Python standard library and does not repeat the exhaustive search:

```sh
python3 -S -B research/char_amsco/astra/utf8_search/target/verify_results.py
```

The verifier pins the result, gate, driver, MDX, dataset, canonical hex, controlled source ledger, and gate artifacts. It reconstructs the four canonical orientations; checks the exact ordered Cartesian cell IDs, factorial totals, first/last orders, witness counts, aggregate counters, and zero-survivor records. This is integrity and accounting verification, not a second 1.6-million-order enumeration. Completeness of the negative search relies on the reviewed generator and its independently regenerated synthetic controls.

Primary endpoint definition: [RFC 3629 section 4](https://www.rfc-editor.org/rfc/rfc3629#section-4).

## Immutable hashes

- Target result: `2687f94d8eb669fc28ab0d1f5dbd134098bc74451e8298d7a0e991cf06ee6b54` (284,409 bytes)
- Gate: `1ca44c7c13d6aaffc16f26615cf6cff3f2aa2c5a4a802f6f8b800bace7e8fbf7`
- Driver: `99bf55ea5e422bd3dce7a8cd64af484399bbcf010b2064bb9d82188ec8ada45f`
- Core: `351f003d91be6ab94046bedc6ef0cc76f77370750a878f185c154cd0d5e3782e`
- Synthetic control source: `69127807d923fddd822cc0f2885408f1a4dcab9d85f166c3b23f4961a4bd0937`
- Synthetic control ledger: `5237b660e4f72ff42f31c7872777cc4c29d7ad42f3d0ce959479cd44a3396f1a`
- Driver-control source: `4a89ed30cba5be094937fb866ff1c7fc3bd8c619b08d94d7674f0413e3c257e3`
- Driver-control ledger: `f73aab636e2a18efb35c5f5b5af498932f300b7ac19f2999689a3e454f90be05`
- Gate builder: `eecbcd4045168f9b1600130525f4ef86ffd01e13dd92a95b973c20611cae9010`
- Canonical MDX: `085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91`
- Dataset: `68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e`
- Canonical normalized hex: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

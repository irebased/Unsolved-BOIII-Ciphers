# ASTRA stronger all-IV byte-column result

Identity: ASTRA. Status: complete.

The preregistered eight-cell run evaluated rectangular FABLE variant B for AES-128 CFB8 with fixed key `Zombies` followed by nine NUL bytes, every external 16-byte IV, widths 13 and 14, four canonical orientations, and the strict ASCII plus five-sequence UTF-8 endpoint.

All eight cells are complete every-IV, every-order exclusions. There are zero unresolved cells. All 108 observed strided chunks reject the necessary endpoint predicate after their first 16 ciphertext bytes.

| Orientation | Width | Rejected chunks | Original first-rank weight | Stronger weight | Status |
|---|---:|---:|---:|---:|---|
| forward | 13 | 13/13 | 13! | 13! | complete |
| forward | 14 | 14/14 | 14! | 14! | complete |
| full_hex_reverse | 13 | 13/13 | 13! | 13! | complete |
| full_hex_reverse | 14 | 14/14 | 14! | 14! | complete |
| byte_reverse | 13 | 13/13 | 13! | 13! | complete |
| byte_reverse | 14 | 14/14 | 14! | 14! | complete |
| nibble_swap | 13 | 13/13 | 13! | 13! | complete |
| nibble_swap | 14 | 14/14 | 14! | 14! | complete |

The original first-column argument also reaches the full factorial weight in these data because every possible first rank rejects: `w × (w-1)! = w!`. The stronger lemma needs only one rejected unavoidable chunk to exclude every order; all chunks reject here. These are two descriptions of the same complete target exclusion and must not be added as independent weight.

The first empty FSA state set occurs at relative chunk offset 16 for 73 chunks, 17 for 24, 18 for 7, 19 for 2, 20 for 1, and 21 for 1. Each result row stores every full ciphertext chunk, its full IV-independent plaintext suffix, hashes, and the first failure trace.

A separate read-only verifier re-extracted all four orientations and checked all 108 chunks without importing the original helper. For every chunk it:

- recomputed the ciphertext-only AES-ECB CFB8 recurrence;
- matched PyCryptodome CFB8 suffixes under two distinct IVs;
- propagated the three possible UTF-8 boundary states;
- matched the stored full bytes, hashes, end states, and first failure;
- verified the exact eight-cell Cartesian scope and `13!`/`14!` certificates.

Run command, from `/private/tmp/rev7-astra-20260909`:

```sh
python3 -B research/byte_columnar/all_iv/run_stronger_target.py --run-target
```

Independent verification:

```sh
python3 -B research/byte_columnar/all_iv/verify_stronger_results.py
```

Evidence:

- results SHA-256: `d45bdb13020a0e0fbb92a1c80417fb58107c96656a1280bc5d3139677c1f83b1`
- independent verifier SHA-256: `674cfabb9a1c8e79fcd71772edadc326af7756813c9a7368abc74d0ffc00315c`
- frozen driver SHA-256: `b56aa5e29b5a5e4b4850add8bd7d0545f141a518830a487a939ad389e587e21d`
- frozen gate SHA-256: `c148795ae92d228c0d2a058b69b213ff87318a2edd5476ecb510df00b2425b4f`
- canonical MDX SHA-256: `085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91`
- extracted ciphertext SHA-256: `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`

This finite exclusion does not cover variant A, ragged columns, prepended-IV framing, other keys or ciphers, other modes, or text outside the registered five-sequence endpoint.

# Stronger all-IV target registration

Identity: ASTRA. Status: controls and source-matched gate ready; Rev7 target not evaluated.

The proposed target has eight cells: rectangular FABLE variant B, AES-128 CFB8 with fixed key `Zombies` followed by nine NUL bytes, every external 16-byte IV symbolically, widths 13 and 14, and four orientations (`forward`, `full_hex_reverse`, `byte_reverse`, `nibble_swap`). The endpoint is TAB/LF/CR, ASCII 32–126, and only `E2 80 {93,94,98,99,A6}`.

For each observed rank, the driver retains the full strided ciphertext chunk, its complete IV-independent suffix after byte 16, both SHA-256 values, the propagated FSA state set, and the first failure offset. A separate implementation verifies the suffix through direct AES-ECB recurrence and PyCryptodome CFB8 under two distinct IVs.

The original first-column predicate assigns `(w-1)!` weight to each rejected possible first rank. The stronger lemma uses the fact that every observed rank is an unavoidable contiguous natural ciphertext chunk under every variant-B order. If any one chunk is invalid from all three possible FSA boundary states, every order and every external IV fails, giving the full `w!` certificate. If no chunk rejects, the cell remains unresolved; it is not a survivor plaintext.

After separate authorization, run once from `/private/tmp/rev7-astra-20260909`:

```sh
python3 -B research/byte_columnar/all_iv/run_stronger_target.py --run-target
```

The gate-only self-test is:

```sh
python3 -B research/byte_columnar/all_iv/run_stronger_target.py --selftest
```

Finite exclusions do not extend to variant A, ragged columns, prepended-IV framing, other ciphers or keys, other modes, or broader text endpoints.

# Rev7 periodic byte-bag target result

Identity: ASTRA.

The registered target evaluated periods 1 through 64 inclusive, XOR and modular-subtraction decryption, and the four canonical hexadecimal orientations. This is 512 labeled cells. Byte reversal makes forward equivalent to byte_reverse up to residue permutation, while full hexadecimal reversal makes nibble_swap equivalent to reverse. Therefore the grid has 256 unique key-existence contexts.

Every cell independently computed the complete 256-bit key-byte mask for every residue with both the fast bitset implementation and the slow per-key reference. All masks matched. The result stores every mask, candidate count and list, every empty residue, and the first observation that made each such residue empty.

For each of the four unique orientation/operation families, every period from 1 through 64 has at least one empty residue mask. Remaining periods: none. Thus none of these 256 exact repeating-key contexts can map every decrypted byte into the declared 165-byte endpoint union.

This is a necessary byte-bag exclusion. A nonempty residue set would not establish valid ordered UTF-8, and this experiment did not run a UTF-8 solver or enumerate Cartesian products of residue keys. The result does not cover periods above 64, other byte operations, changing keys, extra framing or transformations, or bytes outside the literal 201-codeword endpoint.

Artifacts:

- target_results.json: SHA-256 008966a182ee38ff9ffac569e715d91bab8c05cf37ae5c2c6043dc0d6b1c9acc; 8,583,401 bytes.
- run_target.py: SHA-256 6b14c599a1898cd7fd7f993fe99e94cf573efbf22927e7be166081840bf939af.
- Parent controls.json: SHA-256 8e3c80efc2da2a7dce6a10bdf7f55fa12a6d11b594e73fd872148c29969e6bc4.
- Normalized input: SHA-256 5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c.

Reproduce the registered computation only when an output is absent:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/target/run_target.py --run-target

Verify the saved result with a separately written slow per-key mask calculation:

    python3 -B research/rev7-20260909-codex/coverage/periodic_bytebag_controls/target/verify_results.py

The verifier reads the saved target and canonical records and recomputes all masks. It does not enumerate full repeating keys or test ordered UTF-8.

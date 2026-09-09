# Native broad-text target result

Identity: ASTRA.

Target ledger SHA-256: `640a1fb9f2878db0c43d2b4e2dbba7d9b8b3f4a77dd87499244c2bdda9c00fe1`.

All twelve frozen 10,000,000-node prefixes matched the earlier Python ledger exactly before extension. The registered extension then restarted every cipher/orientation cell from the root with a 100,000,000-node cap. No terminal survivor was found.

| Cipher | Orientation | Status | Nodes | Certificate weight | Unaccounted weight | Seconds | Survivors |
|---|---|---:|---:|---:|---:|---:|---:|
| aes128 | forward | capped | 100000000 | 15165136342920 | 5757653545080 | 5.159490 | 0 |
| aes128 | reverse | complete | 34169898 | 20922789888000 | 0 | 1.789960 | 0 |
| aes128 | byte_reverse | complete | 34090259 | 20922789888000 | 0 | 1.776620 | 0 |
| aes128 | nibble_swap | capped | 100000000 | 15166977432434 | 5755812455566 | 5.188310 | 0 |
| blowfish | forward | capped | 100000000 | 15224943754080 | 5697846133920 | 5.912370 | 0 |
| blowfish | reverse | complete | 34849696 | 20922789888000 | 0 | 2.097950 | 0 |
| blowfish | byte_reverse | complete | 34915798 | 20922789888000 | 0 | 2.097650 | 0 |
| blowfish | nibble_swap | capped | 100000000 | 15313038109200 | 5609751778800 | 5.960550 | 0 |
| des | forward | capped | 100000000 | 15334675279920 | 5588114608080 | 7.830840 | 0 |
| des | reverse | complete | 33939864 | 20922789888000 | 0 | 2.699590 | 0 |
| des | byte_reverse | complete | 33938311 | 20922789888000 | 0 | 2.689020 | 0 |
| des | nibble_swap | capped | 100000000 | 15422757018408 | 5500032869592 | 7.925080 | 0 |

Total native extension time recorded by the twelve cells: 51.127430 seconds.

## Finite conclusion

The reverse and byte-reverse orientations completed for AES128, raw-seven-byte Blowfish, and DES. For those six exact cells, rejected plus terminal factorial weight equals 16!, so no global hexadecimal-symbol bijection yields a complete string in the registered ASCII/UTF-8 endpoint.

The forward and nibble-swap orientations for all three ciphers stopped at exactly 100,000,000 DFS entries. They found no survivor in those deterministic prefixes, but their certificates are incomplete. They do not exclude the unvisited mappings and do not constitute an exhaustive negative result.

This conclusion covers only the frozen keys, ASCII-zero IV, CFB8, four orientations, global hexadecimal-symbol bijection, and exact endpoint FSA. It does not exclude other transformations, keys, IVs, cipher modes, repairs, or cipher families.

Every reported survivor would have required independent PyCryptodome and manual CFB8 agreement, exact mapping re-encryption, exact display reconstruction, and terminal FSA state zero. There were no survivors to retain.

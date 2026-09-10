# RC2 and Loki97 five-sequence result

Identity: ASTRA.

The registered eight-cell target run completed once. It covered source-backed RC2 with raw seven-byte Zombies and Loki97 with selected key length 16 in an explicit zeroed 32-byte backing, each under forward, reverse, byte-reverse, and nibble-swap hexadecimal orientations. Every cell used CFB8, an ASCII-zero IV, the fixed five-sequence endpoint, all 16 factorial global hexadecimal-symbol bijections, and the registered one-billion-node cap.

All eight searches completed below the cap. Each produced an exact 16 factorial certificate, zero unaccounted mapping weight, and zero survivors:

| Cipher | Orientation | Nodes | Seconds |
|---|---:|---:|---:|
| RC2 | forward | 341,736,378 | 39.8272 |
| RC2 | reverse | 34,695,046 | 4.10054 |
| RC2 | byte_reverse | 35,092,003 | 4.14209 |
| RC2 | nibble_swap | 338,493,858 | 39.9849 |
| Loki97 | forward | 335,603,028 | 77.5196 |
| Loki97 | reverse | 33,882,351 | 7.91534 |
| Loki97 | byte_reverse | 34,269,689 | 7.96005 |
| Loki97 | nibble_swap | 336,887,237 | 77.5906 |

Total native-reported elapsed time was 259.04032 seconds. The result is a finite negative only for these exact key, IV, CFB8, endpoint, orientation, and global-bijection conventions. It does not exclude other keys, IVs, modes, endpoints, transformations, or cipher families.

The target driver validates every retained survivor through the frozen Python source primitive, CFB8 decrypt and re-encrypt, mapping bijection, exact display reconstruction, and terminal endpoint. There were no survivors to retain.

Artifacts:

- target_results.json: SHA-256 5ee7d589b4917f53f87c4c6b503a4661604b7744f9f1b013bf49a38ddd7454fc
- target_gate.json: SHA-256 bb17ddfba28a84622320e1512fcc7bea157754f9b5b7820c6b8a0a70e61f45e3
- run_target.py: SHA-256 31b5eedd01f3d05f392cc5b7e52e87ebae1f538ac1436647004ec695067fabfb

Run the portable saved-result verifier with:

    python3 -B research/rev7-20260909-codex/hex_cfb/native_text5_siblings_target/verify_results.py

The verifier checks source and gate hashes, independently reconstructs the four target orientations, verifies the exact ordered eight-cell grid, and replays all factorial accounting identities. It does not repeat the DFS search.

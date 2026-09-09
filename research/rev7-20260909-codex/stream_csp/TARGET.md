# Preregistered fixed-keystream target grid

Identity: ASTRA. Status: control-gated and not run.

The fixed grid contains 72 cells: AES128, raw-seven-byte Blowfish, and DES;
historical OFB8 and standard full-block OFB; ASCII-zero, NUL, and SHA-1 raw
Zombies prefix IVs; and forward, reverse, byte-reverse, and nibble-swap
orientations. Each cell has a 1,000,000 accepted-CSP-node cap.

The relation relaxation admits printable ASCII, TAB/LF/CR, and the individual
bytes E2, 80, 93, 94, 98, and 99. Complete relation survivors are counted
separately from survivors of the ordered, terminal-state-zero UTF-8 FSA.

Every cell records exact key and IV bytes, the keystream SHA-256, relation sizes, and empty constrained relations. It also
checks each repeated displayed pair using unrestricted ciphertext-byte support:
the intersection of all 256 possible ciphertext bytes that produce a relaxed
byte at every occurrence. When that unrestricted intersection becomes empty,
the result stores the shortest occurrence prefix encountered that empties it,
including positions and keystream bytes. Such a witness rules out any fixed
displayed-pair-to-ciphertext-byte interpretation for that cell without relying
on nibble bijection or all-different constraints.

Uncapped exhaustion requires rejected plus terminal factorial weight to equal
16!. Capped weights are incomplete lower bounds. Every complete survivor is
validated by direct stream XOR, exact inverse display mapping, full recipher,
and the final endpoint FSA.

Control-only gate:

    python3 -B run_target.py --selftest

Future target command requires explicit GO:

    python3 -B run_target.py --run-target

The driver refuses an existing final result and writes an atomic checkpoint
after each cell. Resume requires the explicit --resume option. The gate freezes
the CSP source and controls, actual-C OFB8 fixture ledger, orientation prototype,
driver, and canonical Rev7 source byte hash.


## Completed result

All 72 cells completed with full 16! certificates and zero relaxed or FSA
survivors. Sixty-eight were root-unsatisfiable and carry unrestricted
fixed-byte repeated-pair witnesses. The remaining four Blowfish/OFB8/NUL-IV
orientations exhausted in 518 accepted nodes each. See RESULTS.md.
target_results.json has SHA-256
f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87.

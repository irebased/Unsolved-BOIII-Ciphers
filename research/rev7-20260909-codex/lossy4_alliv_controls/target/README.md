# Inert generic lossy-four-map all-IV target driver

Identity: **ASTRA**

The logical scope is 12 finalized N=1310 source emission maps by four canonical orientations, or 48 cells. Class `N1310-C01` is exactly the `2013` source map: its complete emission-index tuple is checked against the pinned prior implementation and inventory. Its four already-completed target cells are reused from the pinned prior gate/result and are never searched twice. A future authorized run would therefore evaluate 44 new cells and report all 48 logical cells.

Every cell uses DES CFB8 with `Zombies\0`, 655 natural ciphertext bytes, arbitrary original IV represented by every compatible `C[0:8]` register, and printable ASCII plaintext from offset 8. Root counts are derived per map: 4,096 when natural column 1 is dropped and 256 when column 3 is dropped. The 100,000 live-frontier cap applies per sequential root and the 5,000,000 accepted-state cap per newly evaluated cell. Caps remain INCOMPLETE, and every terminal completion preserves its full ciphertext and plaintext suffix.

Synthetic controls prove the exact ordered 48 IDs, four reuse actions, 44 new-search actions, all orientation inverses, the old-map identity, and production-wrapper behavior for both root shapes and cap paths. They do not repeat the parent's 20,622 terminal-candidate control replay.

Default execution hashes the canonical MDX and dataset without extracting or evaluating their ciphertext. A frozen gate tied to an external preregistration and a separate root GO are required for `--run-target`. Existing result and temporary paths are refused.

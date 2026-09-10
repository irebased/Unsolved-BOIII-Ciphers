# Ordered-chunk adjacency target results

Identity: **ASTRA**

The preregistered 32-cell run completed once. All **32 cells closed**, none remained unresolved, and exactly **183,168 distinct ordered chunk pairs** were evaluated.

Every cell closed through the deterministic certificate using its first two zero-indegree vertices. The stored certificate contains every incoming bad-edge witness required for those vertices. Across all cells this is 4,640 bad-edge witnesses. No Hamiltonian search was performed.

| Cipher and width | Cells | Closed | Unresolved | Ordered pairs | Retained edges | Certificate bad edges |
|---|---:|---:|---:|---:|---:|---:|
| AES-128, 39 | 4 | 4 | 0 | 5,928 | 0 | 304 |
| AES-128, 42 | 4 | 4 | 0 | 6,888 | 0 | 328 |
| DES, 78 | 4 | 4 | 0 | 24,024 | 88 | 616 |
| DES, 91 | 4 | 4 | 0 | 32,760 | 777 | 720 |
| Blowfish, 78 | 4 | 4 | 0 | 24,024 | 77 | 616 |
| Blowfish, 91 | 4 | 4 | 0 | 32,760 | 749 | 720 |
| Blowfish-compat, 78 | 4 | 4 | 0 | 24,024 | 82 | 616 |
| Blowfish-compat, 91 | 4 | 4 | 0 | 32,760 | 706 | 720 |
| **Total** | **32** | **32** | **0** | **183,168** | **2,479** | **4,640** |

Each cell retains the complete kept-edge list, indegrees, outdegrees, weak components, closure reasons, exact pair count, and a SHA-256 over the declared deterministic serialization of all evaluated pair rows. It stores the complete suffix and first-failure evidence for the selected sufficient certificate. Each closed cell certifies `w!` orders impossible for every external IV.

Independent verification reconstructed the exact 32-cell Cartesian scope, recomputed all graph statistics and selected certificates, checked every per-cell factorial weight, and replayed all 4,640 necessary bad edges. The optional full-pair mode separately regenerated all 183,168 pair rows and matched every stored graph digest and kept-edge list. Both modes used PyCryptodome and the established Blowfish-compat word-reversal conjugation; no compiled compatibility binary was required.

The full pretty ledger was 3,682,489 bytes. A minified lossless serialization was 2,037,151 bytes. The publication certificate package is 193,082 bytes. It preserves all outer, cell, and graph metadata and stores each certificate row as `[from_rank, to_rank, suffix_hex]`. The unpacker derives pair hashes from the canonical oriented chunks and derives suffix hashes, lengths, endpoint failures, and fixed boolean fields without cipher evaluation. It reconstructs the exact full pretty ledger SHA.

Artifacts:

- `target_results.json`: 3,682,489 bytes; SHA-256 `d208d2a06218faf16e5caa16bbf13585e39ac7e82b395528e76c20140ec2a6e7`
- `target_results_compact.json`: 2,037,151 bytes; SHA-256 `d771f85b859c5839d3fe15e620234ce0e942476a15c550376bdf3c9bfb07b0a8`
- `certificate_package.json`: 193,082 bytes; SHA-256 `f3df4ac12a5ab3f722e5fa751ef266ae4336cc95617154af5630c4b88852fb65`
- `target_gate.json`: SHA-256 `acf9fbd2918a7a62edacaf680b49f16969bb795e6df30dbdcff51565366a0abc`
- `run_target.py`: SHA-256 `b3147392c6a5384b9c872f33b4127fc4f71e2f14be23858643332176a3e2aed3`

Execution used tool session/process handle **6831** and finished with 32 of 32 per-cell files present. The observed session lasted about 64 seconds; the driver did not record an intrinsic runtime.

Executed once:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/adjacency/run_target.py --run-target
```

Portable certificate replay:

```sh
python3 -B research/byte_columnar/all_iv/adjacency/verify_results.py
python3 -B research/byte_columnar/all_iv/adjacency/verify_results.py --full-pairs
python3 -B research/byte_columnar/all_iv/adjacency/pack_results.py --verify
```

Finite scope: AES-128 widths 39/42 and DES, standard Blowfish, and Blowfish-compat widths 78/91; fixed Zombies keys; CFB8; every external block-size IV; rectangular variant B; four canonical orientations; and the registered five-sequence endpoint. Ragged layouts, variant A, other primitives, widths, modes, keys, endpoints, and graphs requiring Hamiltonian search remain outside this result.

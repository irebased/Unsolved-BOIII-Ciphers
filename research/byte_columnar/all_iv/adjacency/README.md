# Rectangular variant-B ordered-chunk adjacency controls

Identity: **ASTRA**. Controls are synthetic; Rev7 has not been parsed or evaluated.

For a rectangular stream of length `n=w*q`, observed rank `j` exposes the contiguous natural ciphertext chunk `observed[j::w]`. When `q <= b < 2q`, concatenating ordered distinct chunks `A,B` exposes at least one CFB8 plaintext byte after the `b`-byte register. A directed edge `A -> B` exists only when this suffix retains from at least one endpoint boundary state in `{0,1,2}`. No terminal-zero condition is imposed at the pair boundary.

Every true natural column order induces a directed Hamiltonian path. The target method uses only three sufficient impossibility rules:

- at least two vertices have indegree zero;
- at least two vertices have outdegree zero;
- the underlying weak graph is disconnected.

A directed Hamiltonian path can have only one start, only one end, and must be weakly connected. Graphs not closed by these rules remain unresolved; the target performs no Hamiltonian search.

Controls cover exact FABLE rectangular variant-B inversion, all true path edges in arbitrary-IV valid plants, two-IV suffix equality, a UTF-8 sequence crossing the tested pair boundary, adapter provenance, and widths 3–7 checked against both independent graph Hamiltonian enumeration and exhaustive full column orders under two IVs. Cases with `2q <= b` are refused.

The prospective target has 32 contexts: AES widths 39/42 and DES, standard Blowfish, and Blowfish-compat widths 78/91, crossed with four canonical orientations. It uses the fixed Zombies keys, CFB8, every external IV, and the five-sequence endpoint. Every ordered pair is evaluated and independently verified. The result stores the complete kept-edge list and a SHA-256 over a declared deterministic serialization of all pair rows. For a closed cell it persists one deterministic sufficient certificate: all incoming bad-edge witnesses for the first two zero-indegree vertices, otherwise all outgoing witnesses for the first two zero-outdegree vertices, otherwise every bad edge crossing the first weak component in both directions. An unresolved cell retains its complete kept-edge list and no exclusion certificate. Per-cell files are written atomically, then the combined ledger is written once.

Controls were generated with:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/adjacency/controls.py
```

Gate self-test:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/byte_columnar/all_iv/adjacency/run_target.py --selftest
```

No target command is authorized until explicit GO. Finite limits exclude ragged rectangles, variant A, other widths, modes, keys, ciphers, endpoints, and any closure requiring Hamiltonian search.

# Width-13 first-six proof controls

Identity: ASTRA. Target evaluated: false.

Under the deterministic toy block function, the formula and independently materialized full inverse produced the same accept/reject classification on all registered complete orders:

- width 7 start 1: 5,040 orders, 33 retained;
- width 7 start 2: 5,040 orders, 89 retained;
- width 9 start 1: 362,880 orders, 60,168 retained;
- width 9 start 2: 362,880 orders, 60,444 retained.

For width 9, each retained six-rank prefix expanded to exactly six complete orders. Rejected-prefix weight plus retained full orders equaled `9!` for both starts.

Historical-backend cryptographic controls are confined to width 13. There, the controls verified 28 rows, equal 42-byte observed chunks, and nine bytes in the first six natural cells of every row. Bounded formula-versus-full-inverse comparisons covered 1,025 assignments per IV suite for DES, Blowfish, Blowfish compatibility, and RC2, both starts, and two unrelated IVs. The true planted assignment retained the exact same 28 plaintext ninth bytes under both IVs. Manual CFB8 encryption matched the accepted runtime.

The prospective search unit is 1,235,520 prefixes per start, orientation, and backend. Each rejected prefix certifies 5,040 full orders. This package does not execute that search.

Controls ledger SHA-256: `7729b861b73e2326bffb33caf1ba2951278bc8d1d0accee2b61973bed3c10de7`.

No target ciphertext was read, no target result was produced, and the proof does not claim that retained prefixes are valid full plaintexts.

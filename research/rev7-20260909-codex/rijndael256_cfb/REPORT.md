# Synthetic Rijndael-256 CFB8 interval result

Identity: ASTRA  
Target evaluated: false  
Rev7 read: false

All registered controls passed.

- Six complete 256-byte CFB8 streams matched historical C and untouched JavaScript exactly across three explicit NUL-padded `Zombies` key lengths and two IVs.
- Three same-fixed-ciphertext/two-IV controls had different IV-dependent 32-byte prefixes and identical suffixes from byte 32 onward.
- All 21 boundary intervals matched full-mode reference slices, including empty and one-byte post-boundary cases.
- All 168 depth-two and 1,008 depth-three recipes round-tripped and recovered the exact predicted final interval under both IV suites: 1,176 recipes and 2,352 executions.
- Every recipe recorded at least one rejected intermediate binary endpoint while its final known plaintext interval passed. No intermediate endpoint result influenced execution.

The known final interval lengths in the mixed grid range from 320 to 344 bytes of the 384-byte synthetic plaintext. The grid uses all seven accepted existing backends, all three Rijndael-256 key variants, every permitted Rijndael layer position, and all registered transform combinations.

`controls.py` is both the generator and the portable read-only verifier. The ledger retains exact primitive outputs, direct two-IV plaintexts and suffixes, exact final known interval bytes, per-suite ciphertext hashes and IVs, every stage interval/hash/endpoint classification, build commands, tool versions, and dependency hashes.

Result ledger SHA-256: `511aad6d309c05b16a8b2281f69bc748f180af499988016659554324b7f135d3`  
Result ledger size: `6,094,712` bytes

This is control evidence for a possible future delta-cascade experiment. It is not a Rev7 result and does not authorize a target evaluation. Its conclusion is limited to direct same-length binary CFB8 composition with the registered involutions. It does not establish complete historical wrapper behavior or recover IV-dependent prefixes.

Root independently regenerated the complete ledger. Every field matched except four explicitly recorded temporary-library hashes: Rijndael-256, Blowfish compatibility, Twofish and Loki97. The synthetic cryptographic outputs, exact interval bytes, source hashes, recipe identities and all counters matched. The depth-three grid uses seven cyclic existing-backend pairs, as specified in PLAN.md.

Publication uses a lossless zlib/base85 envelope and a bounded standard-library decoder. It preserves every original ledger byte. Follow the README reconstruction step before running the original control verifier in a fresh checkout.

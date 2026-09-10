# Native prefix13 control report

Identity: ASTRA. Target evaluated: false.

The native engine exactly matched the accepted Python proof on 524,160 complete synthetic prefix evaluations:

- four backends;
- widths 7 and 9;
- both continuous starting patterns;
- every ordered six-rank assignment;
- every retained six-rank tuple and computed plaintext-byte tuple;
- survivor digests, early-rejection block counts, and factorial weights.

Each of the 16 complete grids contained both retained and rejected prefixes. Width 7 used 5,040 prefixes with completion weight one. Width 9 used 60,480 prefixes with completion weight six.

At width 13, all eight bounded 4,096-prefix scans rejected their deterministic lexicographic prefixes and matched Python exactly. A separate planted true assignment was evaluated through the native `--evaluate` path for each backend and start; it retained and matched all 28 Python-computed ninth plaintext bytes. This demonstrates both outcomes without claiming that the bounded prefix begins at the planted assignment.

Native block controls covered 256 backend/block pairs. Full-byte CFB8 controls covered every byte under two IVs for each backend, with exact encryption and decryption equality. The historical RC2 source was built only in a temporary directory.

The benchmark examined eight million additional synthetic prefixes. Rates ranged from about 5.57 million to 9.92 million prefixes per second. The linear estimate for 39,536,640 prefixes across 32 prospective contexts is 5.21 native seconds, excluding orchestration and verification.

Frozen hashes:

- `native.cpp`: `f9c731e222381597dcb03d00155549f12fb6d82923975b13f2a18d3c05e631d0`
- `native_controls.py`: `901def5c5a4f329354611d9930f55b441619ae9fb2ff219aed0e560329b4221d`
- `native_controls.json`: `97eb5e5783c8c0aedfe98c27e112da8ffb2a641fa284a6ff3690de867be62766`

No Rev7 data was read or evaluated. The result validates a necessary A105 prefix filter, not full UTF-8 plaintext, a recovered IV, a complete column order, or a solve.

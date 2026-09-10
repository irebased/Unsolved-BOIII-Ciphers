# Even-block empty-rectangle certificate

Identity: **ASTRA**. This target-free package derives a square-independent necessary condition for even-block 4×4 Bifid output under one fixed square or the proved construction with distinct fixed ciphertext-coordinate and plaintext-output squares.

For every paired ciphertext-symbol edge `(a,b)`, the output high nibble is the plaintext-square symbol at `(row_cipher(a), row_cipher(b))`. Bag213 contains no byte from `0x10` through `0x1F`, so high nibble `1` must never occur. If plaintext-square symbol `1` has coordinate `(r,c)`, let `A` be ciphertext-square row `r` and `B` row `c`. Each has four symbols, and the observed directed pair graph must omit every edge in `A × B`.

The implementation deliberately relaxes square geometry: it searches every one of the 1,820 four-symbol sets `A` and permits any four-symbol `B`, including overlaps that real square rows cannot have. For each `A`, it intersects the missing-out-neighbor masks of its four vertices. If every intersection has population below four, no empty 4×4 rectangle exists even in this relaxed family, so every fixed-square construction forces high nibble `1` and bag213 is impossible. If the maximum is at least four, this test is unresolved.

The same reasoning actually forces every one of the 16 high-nibble symbols when no empty rectangle exists: each plaintext-square symbol supplies some coordinate `(r,c)` and hence some real row pair `A,B`. The package does not enumerate row partitions because the arbitrary-set relaxation is sufficient for negative certificates.

Controls preserve all 1,820 row-set/missing-mask records per graph and compare them against direct edge enumeration. Complete, empty, planted-rectangle, and deterministic random graphs cover both outcomes. Six full 546-byte printable plants cover periods 16, 562, and 972, same and distinct fixed squares, literal coordinate decryption, the accepted two-square pair inverse, and the known missing rectangle for high nibble `1`. No Rev7 data is read.

Run `python3 -B controls.py`. Generation is separate with `--regenerate NEW_PATH` and refuses overwrite.

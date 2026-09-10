# Saved padded-tail occupancy result

Identity: **ASTRA**.

The preregistered post hoc evaluation completed once over all **3,312** saved RA READY rows whose primitive is a block cipher, whose mode is ECB or CBC, and whose 546-byte input is not block aligned. It performed no cryptographic operation and did not modify the original RA result.

All **3,312** rows satisfy the conditional prefix bound; none is incomplete and none has an unsupported candidate-length interval. For each row, the stored first 544 plaintext bytes define `Q = P.rstrip(NUL)`. The possible padded-result lengths are bounded by `len(Q)` and the applicable padded length, and every integer length in each interval is covered by the published occupancy table.

- `len(Q)` ranges from 543 to 544.
- `D(Q)` ranges from 209 to 239.
- The largest applicable threshold is 192.
- The smallest row margin, `D(Q) - max_threshold`, is 19.

Therefore no arbitrary decrypted replacement final block, followed optionally by trailing-NUL removal, can make any of these rows pass the published low-occupancy screen, provided the compared padded ECB/CBC model leaves the first 544 plaintext bytes unchanged. This conclusion is finite for the 3,312 saved rows and this occupancy table.

The proof does not establish historical PHP or tool equivalence, KDF or IV equivalence, or behavior of other modes. It also does not perform a padded decryption: it relies on ECB/CBC's block-local prefix dependency and allows every possible replacement tail.

Artifacts:

- `saved_bound_results.json`: 2,830,312 bytes, SHA-256 `40db1f8ae0a80153ff0caa9808d2bf2a830eabed2de1b1700da82331b879259f`
- `run_saved.py`: SHA-256 `547128efe40e5013948d2f039b890cbd427030daafbdba02ec73a12280f39024`
- frozen original RA result: SHA-256 `448ff7f95d9d07a334439ec4ddca831da5d15173bcba104858aed337f4cd67cb`

Replaying the default command verifies only the target-free controls. The saved evaluation is intentionally not rerun automatically.

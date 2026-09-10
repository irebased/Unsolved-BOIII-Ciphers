# Synthetic byte-AMSCO control result

Identity: ASTRA. Target evaluated: false.

The independent forward and inverse formulations agree for every registered small fixture and permutation. The length-546 boundary ledger covers widths 2 through 9 and both continuous starting patterns. Separate shorter cases confirm that a truncated final two-byte cell is assigned one byte and changes its natural column's observed chunk length accordingly.

All seven accepted backends passed planted CFB8 composition controls:

- AES-128, DES, Blowfish, Blowfish compatibility, RC2, Twofish, and Loki97;
- two unrelated external IVs per backend;
- all four canonical display orientations;
- exact byte-AMSCO inversion;
- exact plaintext suffix recovery after the backend block boundary; and
- exact full decrypt/re-encrypt recovery of the generated ciphertext.

The suffix result uses the CFB8 identity after one full ciphertext block and therefore does not recover or constrain the external IV. It proves the synthetic composition and future all-IV search framing only.

The exact prospective geometry grid for widths 2 through 9 is 3,272,896 transforms. A 50,000-prefix Python benchmark gathered 64 inverse bytes at about 12,476 prefixes per second, corresponding to a linear geometry-only estimate of about 262 seconds. Cipher work, endpoint checks, process overhead, and full survivor reconstruction are excluded. An optimized target should request indexed window bytes and reject early.

Frozen controls ledger SHA-256: `767d651729055d1d6fa202e8983635d3afafd46d06729924569db7260ed21175`.

No Rev7 bytes were read and no target experiment, gate, or publication action occurred.

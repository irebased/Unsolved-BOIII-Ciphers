# Result

The unchanged PECL-style C source produced ciphertext lengths divisible by four for all 17 controlled inputs, including 545, 546, and 547 bytes, and decrypted every result exactly. The observed lengths matched `4*(ceil(n/4)+1)`. The pinned raw `btea` source emits `4*max(2,ceil(n/4))` bytes.

Therefore a complete standard word-serialized XXTEA value followed solely by byte-length-preserving binary layers cannot be the source of a final 546-byte hex-decoded value. A decryptor can permissively zero-fill a 546-byte input to 548 bytes, as the saved raw JavaScript does. Such a call is still outside the producer range of standard word serialization and therefore cannot establish a length-preserving XXTEA roundtrip from a 546-byte serialized ciphertext.

Pinned prior FABLE evidence records a separate 113,760-job scan over 10 modulo-four trims, four orientations, 1,422 keys, and PECL/raw decoders, with zero retained survivors. This audit verifies that source/result relationship without rerunning its target scan. The scan’s control comment says 544 bytes, but the actual literal is 313 bytes.

The result leaves the documented escape conditions open and does not exclude XXTEA-derived feedback constructions or chains with encoded-text, truncation, headers, extraction, or other length changes. No new Rev7 decryption was performed; the earlier saved scan result was read only for bookkeeping.

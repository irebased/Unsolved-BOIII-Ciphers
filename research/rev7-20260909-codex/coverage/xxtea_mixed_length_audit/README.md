# ASTRA XXTEA mixed-chain length audit

This source-backed control isolates one narrow invariant. Both pinned whole-buffer framings in the pinned implementation serialize complete 32-bit words:

- the PECL-style wrapper encrypts `ceil(n/4)` data words plus one plaintext-length word, producing `4*(ceil(n/4)+1)` bytes;
- the raw `btea` route pads to at least two words and produces `4*max(2,ceil(n/4))` bytes.

Consequently, after a complete whole-buffer XXTEA serialization, any composition containing only byte-length-preserving binary operations—CFB or stream transformations, XOR, reversal, or byte permutation—still has length divisible by four. A final hex representation of those bytes decodes back to that same divisible-by-four length. It cannot equal the canonical 546-byte Rev7 binary length, whose residue is two.

The appended variable/plaintext-length word does not escape the proof: it adds one complete 4-byte word. For positive input lengths, actual compiled controls use the unchanged pinned C implementation for input lengths around word boundaries and 545–547 bytes, assert the formula, and decrypt every ciphertext exactly. Raw-framing formula assertions are derived from the pinned JavaScript source; that raw path is source-inspected rather than executed by this control. A raw decoder may accept 546 input bytes by zero-filling its last partial word, but such permissive decoding is not the inverse of a standard word serializer that produced 546 bytes.

This is a framing exclusion, not an algorithm-family exclusion. It does not cover an 8-byte XXTEA-derived feedback primitive, UTF-8-expanded or Base64 text retained as the final binary layer, truncation, headers or insertions, prefix/suffix extraction, or any other length-changing framing. Hex or Base64 that is merely transport for the complete serialized bytes preserves the underlying modulo-four invariant after decoding.

The package also freezes FABLE’s earlier XXTEA scan source and saved result: 10 modulo-four trims, four orientations, 1,422 keys, and two variants produced 113,760 jobs and zero 90%-printable survivors. That target scan is source/data evidence only and is not rerun here. Its supposed 544-byte control plaintext is actually 313 bytes because the literal is shorter than the slice limit; its recovery remains a valid shorter control.

The executed sources are immutable paths at old-ciphers commit `7c43c6ae65f49bd7504494d9ca3c55ce2e2496b6` (2026-09-07). Its C header says it was ported from `xxtea-pecl`. The official PECL package index dates release 1.0.11 of that string-oriented extension to 2016-01-05 and explicitly distinguishes it from the original uint32-array interface. This audit does not assert byte identity between the 2026 port and the 2016 tarball. The package records their URLs and SHA-256 hashes. It evaluates no Rev7 ciphertext.

Reproduce:

```sh
python3 -B research/rev7-20260909-codex/coverage/xxtea_mixed_length_audit/audit.py
```

To create a separate ledger without overwriting the frozen one:

```sh
python3 -B research/rev7-20260909-codex/coverage/xxtea_mixed_length_audit/audit.py --regenerate /tmp/xxtea-controls.json
```

Identity: ASTRA.

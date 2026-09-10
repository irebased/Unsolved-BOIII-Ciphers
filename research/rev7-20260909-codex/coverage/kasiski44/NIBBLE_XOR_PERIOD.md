# Hex-symbol periods and byte-key periods

Identity: ASTRA. This is a target-free algebraic coverage statement, not evidence that Rev7 uses a repeating key.

Let a nibble-XOR key be k[0], ..., k[m-1], repeated over an even-length hex-symbol stream. Pair the symbols at indices 2j and 2j+1 into a byte. The corresponding byte key is

```
K[j] = 16*k[(2*j) mod m] + k[(2*j+1) mod m]
q = m / gcd(m, 2)
```

Because 2q is a multiple of m, K[j+q] = K[j]. Thus q is a sufficient byte period; the minimal period may be smaller. The high and low bits are disjoint, so applying nibble XOR independently is exactly byte XOR by K[j]. Initial key phase is absorbed into a cyclic shift of k and is covered by arbitrary byte keys.

Consequently, an all-byte-keys rejection at byte period 19 also rejects nibble-XOR keys with hex-symbol periods 19 and 38; byte period 57 covers hex-symbol period 57. For odd m, the paired byte key has dependencies between its high and low nibbles, but allowing all byte keys only enlarges the family. Rejecting that superset is sound. Message length need not be divisible by either period.

This claim applies to nibble XOR. Independently subtracting each hex digit modulo 16 is not the same as byte subtraction modulo 256, which can borrow from the high nibble. Neither operation closes arbitrary periodic substitution, polyalphabetic alphabets, fractionation, or a different placement of the AMSCO layer.

The controls exhaust all 65,536 input-byte/key-byte identities and test 912 deterministic streams across every m from 1 through 114, including wraparound and incomplete final periods. They read no Rev7 data.

```sh
python3 -B research/rev7-20260909-codex/coverage/kasiski44/nibble_xor_period.py
```

# Four-character-row source inventory result

Identity: **ASTRA**

Of all 9,000 positive four-digit keys, exactly **864** emit four characters from a complete six-character row. The complete all-key emission-count distribution is retained in the ledger; the other 8,136 keys are outside this restricted family.

Using zero-based natural columns, the qualifiers divide into three retained-column shapes:

- columns 0 and 2 retained: 504 keys, dropping both one-character columns 1 and 3;
- columns 1, 2, and 3 retained: 192 keys, dropping the two-character column 0;
- columns 0, 1, and 3 retained: 168 keys, dropping the two-character column 2.

The quotient/remainder proof reduces all possible even natural lengths for an observed 1,092 characters to six exact candidates. Measured partial-row contributions are:

- remainder 0: `t=0` for all 864 keys;
- remainder 2: `t=2` for 744 keys and `t=0` for 120;
- remainder 4: `t=3` for 648 keys, `t=2` for 168, and `t=4` for 48.

Therefore the only compatible even lengths are:

| Natural characters | Natural bytes | Qualifying key memberships | Exact emission maps |
|---:|---:|---:|---:|
| 1,636 | 818 | 48 | 12 |
| 1,638 | 819 | 864 | 14 |
| 1,640 | 820 | 120 | 6 |

Lengths 1,632, 1,634, and 1,642 have no compatible qualifier. Membership totals overlap: the 48 keys compatible at 1,636 and the 120 compatible at 1,640 are also among the 864 compatible at 1,638.

For the first eight natural ciphertext bytes, the 32 exact map classes have only two geometry-level root-domain sizes: 14 classes leave five unknown nibbles, or 1,048,576 assignments; 18 leave six, or 16,777,216 assignments. These are structural counts only. No root assignment, CFB state, cipher, or plaintext was evaluated.

The independent map equals the pinned original `legacy_encode` for two complete-row fixtures under all 9,000 keys. It also matches one deterministic fixture at each of the six candidate lengths for every qualifier, including all partial-row fallback behavior. The ledger hard-asserts the exact qualifier, retained-shape, partial-distribution, length-membership, class, and root-domain totals.

This is prioritization data for one bounded malformed-key family. It is not evidence that Rev7 used this tool or any of these keys, and it does not cover other input widths, frontend coercions, or emission counts.

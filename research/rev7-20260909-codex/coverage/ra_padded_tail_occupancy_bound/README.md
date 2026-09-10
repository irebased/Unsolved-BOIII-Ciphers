# Padded-tail occupancy lower bound controls

Identity: **ASTRA**. These controls are synthetic and target-free. They establish a small lemma for later post hoc analysis of saved RA outputs; they do not decrypt or inspect Rev7.

Let `P` be the 544-byte plaintext prefix produced by decrypting 68 complete 8-byte blocks, 34 complete 16-byte blocks, or 17 complete 32-byte blocks. Let `Q = P.rstrip(NUL)`. ECB and CBC make each plaintext block depend only on its own ciphertext block, and for CBC also on the preceding ciphertext block. Extending the final partial ciphertext with padding cannot alter those first 544 plaintext bytes.

For every arbitrary decrypted replacement tail `T`, both `P || T` and its trailing-NUL-stripped form begin with `Q`. Therefore:

- `D(output) >= D(Q)`;
- `len(Q) <= len(output) <= padded_length`;
- if `D(Q)` exceeds the largest published occupancy threshold over every supported length in that interval, no possible final block can flag.

For a 546-byte ciphertext the padded lengths are 552, 560, and 576 for block sizes 8, 16, and 32. The largest published threshold over lengths 544 through 576 is 192. The later saved-result pass must calculate each row's actual `Q`; these controls deliberately do not.

The tests exhaust small tails over a three-byte alphabet for prefixes with several trailing-zero shapes, test representative production-size arbitrary tails, and distinguish short and out-of-range scorer statuses. A low-alphabet prefix and an interval containing no supported scorer length explicitly fail to prove exclusion. The result does not establish historical PHP behavior, C-wrapper equivalence, a KDF, an IV, or another cipher mode.

Read-only replay:

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/coverage/ra_padded_tail_occupancy_bound/controls.py
```

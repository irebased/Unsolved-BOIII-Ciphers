# Review finding

Identity: **ASTRA**. Target evaluated: **false**.

RA commit `e127b8d6c17f567b930fe67624d3ea199528b775` correctly repairs the execution defect that made `reverse_words` see compacted one-token input. The same verbatim-input helper now feeds ordinary sweeps and `verify --recompute`, and variant masks preserve their compact-coordinate meaning across raw whitespace. Eight focused synthetic tests passed.

The commit does not yet make its new staged-input metadata a verified certificate. Claim verification ignores that object. Its XF census is computed before decryption from the first pre value, while T3 applies XF after layer 1; it therefore cannot describe actual T3 XF inputs. The pre collision census is also one representative variant, despite broader warning wording. These issues should be fixed or explicitly relabeled, but they do not invalidate the repaired candidate bytes or Merkle recomputation.

Frozen modified-source hashes:

- `sweep.rs`: `59465e5c1d2d43ef102bbbc41d6dd2930ab7f29eeb753f60825a1bcf83663dcf`
- `variants.rs`: `6199e8658bfa4ce0cba1043b75a5a667a37f43203d9f32c80109c5711959782b`
- `Cargo.lock`: `03f3b58196c11fcd795d1ebffc97b29e441785989e4e44ebfb568be945198dd6`

This review says nothing about the outcome of FABLE's running T3 search, primitive conformance, oracle calibration, or coverage outside this commit.

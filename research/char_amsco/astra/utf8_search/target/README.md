# Inert RFC 3629 character-AMSCO target harness (ASTRA)

This directory contains a target driver and synthetic driver-wiring controls. It has no target result. Until a reviewed gate exists and root issues a separate GO, only the hash-only self-test is authorized.

## Frozen prospective scope

The registered valid-permutation model uses original-PHP character AMSCO widths 2 through 9, fixed start 21, four canonical hex orientations, and ten fixed CFB8 backends. Every width permutation is enumerated once. The exact workload is 1,636,448 column orders and 16,364,480 backend contexts in 32 cells. There is no cap. A cell is complete only after exactly width-factorial orders and ten times that many contexts, with zero unexamined entries.

For each order, the indexed gather reconstructs ciphertext bytes directly from natural nibble positions. The known CFB8 suffix begins after the backend block size. An eight-state RFC 3629 DFA accepts all Unicode scalar encodings, including ASCII NUL and controls. Its left-cut initial set is boundary/remain1/remain2/remain3; acceptance at the true end requires boundary.

Every evaluated order contributes to a canonical row-stream SHA-256. Every rejected backend contributes its first byte-or-terminal witness to a second canonical SHA-256 and reason counts. Each cell retains its first and last row. Every surviving order/backend/full suffix is retained and independently checked through the full geometry inverse/forward reconstruction, Python's strict UTF-8 decoder with the four registered prefixes, and full CFB8 decryption/re-encryption under two IVs.

The output and per-cell checkpoint are written atomically. Existing output or checkpoint files are refused. The compact negative digests and accounting are execution evidence; they are not a second exhaustive search.

## Safe checks

This command hashes the MDX and dataset files without extracting, parsing, orienting, decrypting, or evaluating their ciphertext:

```sh
python3 -S -B research/char_amsco/astra/utf8_search/target/run_target.py --selftest
```

The driver wiring ledger uses a synthetic width-3 fixture, ten named identity-CFB mocks, and a two-order limiter through the exact production scan and survivor replay path:

```sh
python3 -S -B research/char_amsco/astra/utf8_search/target/driver_controls.py
```

Regeneration writes only a new path:

```sh
python3 -S -B research/char_amsco/astra/utf8_search/target/driver_controls.py --regenerate /tmp/astra-utf8-driver-controls-new.json
```

The gate builder is intentionally not executed by this preparation. Root must review the frozen hashes, add the public FABLE reference, create the gate, and issue a separate GO before this command is authorized:

```sh
python3 -B research/char_amsco/astra/utf8_search/target/run_target.py --run-target
```

## Limits

UTF-8 validity is a necessary byte condition and does not establish readable plaintext. The IV-dependent prefix remains unknown. This scope covers valid permutation keys only; repeated-label lossy PHP keys are separate. It does not broaden keys, modes, encodings, framing, widths, starts, or cipher conventions.

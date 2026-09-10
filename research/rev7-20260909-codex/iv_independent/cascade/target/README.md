# Draft: every-IV CFB8 cascade target (ASTRA)

This directory contains a target driver draft only. There is no gate and no target result. Running the target is impossible until the root reviewer creates a hash-pinned `target_gate.json`, records the FABLE preregistration, and gives an explicit GO.

## Registered model

The proposed finite grid applies the accepted direct-binary CFB8 interval theorem to the canonical 546-byte stream. It uses the seven source-controlled backends and fixed `Zombies` key conventions in `cascade/runtime`, every independent external IV at every layer, depths one through three, four outer orientations, and four involutions at every interlayer boundary.

The exact endpoint counts are:

- depth 1: `4 × 7 = 28`;
- depth 2: `4 × 7² × 4 = 784`;
- depth 3: `4 × 7³ × 4² = 21,952`;
- total: `22,764` unique deterministic case IDs.

Each layer maps a known ciphertext interval `[L,R)` to plaintext `[min(L+b,R),R)`. Byte reversal maps the interval to `[N-R,N-L)`; nibble swap preserves its coordinates; full hexadecimal reversal combines both. Empty intervals are inconclusive.

Every endpoint first receives the A105 necessary byte filter, then the strict boundary-aware FSA for TAB/LF/CR, ASCII 32–126, and UTF-8 `E2 80 93/94/98/99/A6`. The initial state is `{0}` only at the stream start and otherwise `{0,1,2}`. The required terminal state is `{0}` only at the stream end and otherwise `{0,1,2}`. A rejected intermediate endpoint never prunes its children.

Rejected cases retain the interval, digest, classification, and first byte/FSA witness. Retained and empty-inconclusive cases retain the complete interval bytes and are replayed as full cipher chains under two independent IV suites, including exact inverse transforms and re-encryption to the oriented outer bytes. Standard primitives use PyCryptodome `MODE_CFB`; Blowfish compatibility uses the independent word-conjugation recurrence; Twofish and Loki97 use the pinned temporary source builds already gated by KAT and solved-source controls.

## Draft self-test

The self-test hashes the MDX file but does not extract, parse, orient, decrypt, or evaluate its ciphertext. If a gate exists, it must pass the complete artifact and MDX hash checks:

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/run_target.py --selftest
```

It asserts exactly 28, 784, and 21,952 unique IDs and checks pure endpoint boundary fixtures. The eventual target command remains unauthorized until the final gate exists.

## Result representation plan

The working JSON uses one row per deterministic case. Rejections store only a first witness; complete interval hex is restricted to retained or empty-inconclusive cases. Checkpoints are atomic after each outer orientation. The registered run has no resume mode: any existing result or checkpoint is refused, so an interrupted run cannot silently combine temporary native builds or partial executions.

If retained bytes make the result unsuitable for publication, a later deterministic lossless pack will table the Cartesian path fields and hex payloads while preserving every original JSON field and exact unpacked SHA-256. A portable verifier will reconstruct the full result in memory, verify the 22,764-ID Cartesian scope and summaries, re-evaluate stored endpoint witnesses/candidates, and optionally rebuild the source backends for cryptographic replay. No such pack or verifier is claimed before a result exists.

## Limits

This model covers same-length aligned direct-binary CFB8 layers with the registered fixed keys and four transforms only. It does not cover interposed encodings, transpositions, padding changes, truncation, framing, key variants, other modes, or depths above three. Retained endpoint bytes would be candidates, not a solved plaintext; bytes outside their final known interval remain unknown.

## Synthetic driver controls

`controls.py` uses the production traversal and evidence recorder on synthetic ciphertext only. Seven direct plants cover every backend. A depth-two AES/DES plant proves that a rejected intermediate node still expands to its retained child. A depth-three Blowfish-compat/Twofish/RC2 plant uses byte reversal followed by full-hex reversal. Every retained leaf is replayed and re-encrypted under two IV suites through the independent full-CFB references. Additional fixtures distinguish stream-boundary state 0 from internal dependent UTF-8 states and treat an empty interval as inconclusive. A compact branching control traverses 584 endpoints across two backend choices at each depth, all four transforms at both boundaries, and all four outer orientations. Every branch is checked by full-reference decryption and the separate endpoint oracle; the ledger retains exact counts and a deterministic aggregate digest rather than duplicating 584 rows.

Read-only structural verification:

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/controls.py
```

Cryptographic regeneration requires a new, nonexistent directory and never reads Rev7:

```sh
python3 -B research/rev7-20260909-codex/iv_independent/cascade/target/controls.py \
  --regenerate-dir /tmp/cascade-target-controls-new
```

The future gate helper is root-operated only after FABLE preregistration. Its default self-test prints the proposed manifest without writing a gate.

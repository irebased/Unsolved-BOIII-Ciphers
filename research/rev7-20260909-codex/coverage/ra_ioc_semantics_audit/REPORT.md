# `ra` IoC scorer semantics audit

Identity: **ASTRA**.

## Finding

`longest_scored_region_among_passes: 546` means that at least one passing candidate supplied a 546-byte tail to the scorer. It does **not** mean that 546 letters, printable bytes, or bytes of prose were observed.

The exact source establishes the distinction:

- `ra-oracle/src/lib.rs` lines 280–283 computes IoC after filtering the tail to ASCII letters and gates on at least 90 such letters.
- The same score constructor records `scored_len: tail.len()` at line 289, before and independently of that filter.
- `ioc.rs` lines 116–139 drops every non-ASCII-letter byte, folds case, and computes coincidence from the remaining 26 counts.
- The `ioc-english` oracle has no printable-byte gate. A pass requires only at least 90 filtered letters and IoC at least 0.055.
- `ra-cli/src/sweep.rs` lines 2169–2173 groups passing candidates by this tail byte length, and lines 2707–2710 reports only the maximum key of that map.

The copied actual Rust module and a wrapper around its private gate constants confirm the result. A 546-byte input consisting of 90 `A` bytes followed by 456 zero bytes reports:

```
scored_len = 546
letter_count = 90
IoC = 1.0
passed = true
```

This is a direct counterexample to interpreting the field as full-message textual signal. A realistic 221-byte English paragraph embedded in nonletter bytes likewise reports `scored_len=546`, 175 letters, IoC 0.0710016420, and passes. A deterministic xorshift-generated 546-byte uniform-byte mechanics control contains 114 ASCII letters, IoC 0.0385033380, and fails. That single random fixture is not a significance experiment.

## Stored claim

The frozen claim reports 346,816,512 evaluated candidates, 513 passes, a maximum scored tail length of 546 overall and among passes, and expected false positives 2,998.4411437619196. Those fields are internally consistent as aggregate metadata. The claim contains neither the 513 hit records nor the scored-length histogram used to compute the expected total. It therefore does not reveal the passing 546-byte candidate’s filtered letter count, bytes, chain, or score, and the expected-false-positive total cannot be reconstructed from the claim alone.

The maximum establishes only these source-backed facts: at least one passing output had a 546-byte scorer tail, at least 90 of those bytes were ASCII letters, and their filtered IoC reached 0.055. A random 546-byte output is expected to contain about 111 ASCII letters, so the 90-letter gate does not itself imply readable content at this length.

## False-positive estimate

The implementation models a uniformly random byte string in two stages. It computes the exact binomial probability that at least 90 of `n` bytes are ASCII letters, then multiplies by a fixed `1e-4` conditional IoC-tail factor. The latter is described in source as a conservative empirical value derived from 20,000,000 random-letter trials per calibration length, with the worst measured rate at 90 letters.

For `n=546`, the analytic letter-gate probability is 0.989992972101835. The code’s resulting estimated pass probability is 0.00009899929721018351 per candidate. If all 346,816,512 candidates had length 546, that model would predict about 34,334.6 passes. Other scored lengths could explain the difference under this formula; the missing histogram prevents reconstruction of the reported aggregate.

This quantity is a model-based expectation, not a guaranteed bound or a p-value for the observed 513. The conditional factor is empirical, and the stored aggregate is insufficient to recompute or diagnose the full distribution.

## Evidence and reproduction

The audit freezes the exact `ioc.rs`, `lib.rs`, `sweep.rs`, and claim bytes from `ra` commit `e6c282187cc8a555580349d819210b544e5417b1`, with their SHA-256 values in `audit.json`.

```sh
cd research/rev7-20260909-codex/coverage/ra_ioc_semantics_audit
python3 -B audit.py
```

The verifier compiles and runs the copied `ioc.rs` tests directly with Rust 1.96.1. For the custom fixtures it changes only leading inner documentation comments to ordinary comments in a temporary generated compilation unit, embeds the otherwise exact module body, and adds wrappers exposing the private constants and letter counter. An independent Python implementation reproduces every fixture’s tail length, letter count, IoC, and pass decision.

No Rev7 output is decrypted or rescored, and no sweep is run. The audit addresses only scorer/report semantics and the limits of the retained claim fields.

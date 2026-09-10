# Mixed-case lossy `2016` target results

Identity: **ASTRA**

The frozen 16-context scan completed exhaustively within both registered caps and retained no plaintexts. This excludes only the registered ASCII word grammar (space-delimited lowercase, Titlecase, and ALLCAPS words) under the literal lossy CrypTool AMSCO key `2016`, the two registered ciphers, two IVs, and four orientations.

## Counts

- Complete contexts: 16
- Incomplete or capped contexts: 0
- Retained solutions: 0
- Natural ciphertext length: 819 bytes
- Observed lossy ciphertext length: 1,092 hexadecimal characters

Fifteen contexts have an empty frontier after byte 1. `forward|aes128|nul` has frontier counts `1, 2, 1, 1, 2, 0` and becomes empty after byte 6; it accepted seven prefix states in total.

## Independent certificates

`verify_results.py` independently extracts and orients the canonical input, reconstructs the `FF,0F,F0` masks, computes CFB8 keystream bytes with PyCryptodome ECB, and carries a separately coded four-state word DFA. It reproduces every stored frontier count, accepted-state count, block-call count, and first empty prefix.

For the 15 byte-1 exclusions, the sole implied plaintext byte fails the DFA. At the exceptional byte-6 exclusion, 106 final branch attempts were checked: 52 fail the DFA transition and 54 fail the observed ciphertext mask; none survives. The certificate ledger preserves every final branch attempt.

## Reproduction

```sh
cd /private/tmp/rev7-astra-20260909
python3 -B research/rev7-20260909-codex/homophonic/lossy2016_case_controls/target/verify_results.py
```

The target search itself was run once with:

```sh
python3 -B research/rev7-20260909-codex/homophonic/lossy2016_case_controls/target/run_target.py --run-target
```

## Hashes

- Gate: `775cb1ca73b30b286075d27bc8b7b7ef48a14220ddd3546cc5db6914b69a4840`
- Full result: `813ced86f6b41ba1418e641bfb72cff5e760c9e5a5226fb7ee9618058fd9f4f5`
- Independent verifier: `8af0968030b20f260e378823cf4320fc7b8e5fcf972d2b19e4da23e5dd691f93`
- Empty-prefix ledger: `451b9f3f376b1825bda1db14081abbd56e89d04008faff9b2833acebeeca8a25`

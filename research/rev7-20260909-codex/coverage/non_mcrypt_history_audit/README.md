# ASTRA non-libmcrypt history audit

This read-only audit checks a pinned local issue snapshot, coverage notes, solved BO3 records, and a frozen excerpt of the contemporaneous session state for the claim that no non-libmcrypt modern cipher or wrapper had previously been tested against Rev 7. It runs no cipher and reads no Rev 7 ciphertext. The mutable session-state file is not a dependency.

The blanket claim is contradicted by retained experiment summaries in the saved record. Their original target scripts and result ledgers were not available in this audit package and were not re-executed. Issue comment `5600941685` records an XXTEA four-hex-insertion repair grid with NUL-padded `Zombies` and `TheGiant`, including 286,523,392 combined repair parameters under a compressed-member detector. Comment `5600942737` separately records 148,291 representations for the Chris Veness XXTEA serialization bug and 22 unchanged literal-hex cases. Those are narrow framing, repair, and wrapper experiments; a new XXTEA run with different framing or keys can still be new.

The record also contains source-specific work outside the libmcrypt algorithm list: a complete 2^32 CryptoJS Rabbit password-wrapper weakness in two direct orientations, plus bounded RC4Drop, RabbitLegacy, CipherSaber, CryptoJS/Veness, and specified envelope branches. These results remain conditional on their exact wrappers and endpoints.

XTEA must remain distinct from XXTEA. XTEA was already named in FABLE001's libmcrypt sweep, and the local solved Rev12 documentation independently records `XTEA (CFB)`, key `Zombies`, and ASCII-zero 16-byte IV. Conversely, the local The Giant 4 MDX/data are stale and still say unsolved. The current XXTEA provenance for The Giant 4 comes from the solver report retained in the project, not from that stale local MDX:

- https://www.reddit.com/r/CODZombies/comments/1w9e5ib/solved_thegiant_cipher_solved_after_3958_days/

A mechanical standalone-term inventory over every body line in the pinned issue snapshot found no raw-text matches for TEA, RC5, RC6, IDEA, Camellia, or ARIA. The only SEED matches describe deterministic PRNG/CLI seed metadata, not the SEED cipher. Manual review of the pinned coverage summary and local audit filenames likewise found no named target experiment for those algorithms. That is a bounded history finding, not proof that no private or community test exists. Work launched by FABLE after this snapshot is also outside this prior-coverage claim.

Reproduce the source assertions and inventory with:

```sh
python3 -B research/rev7-20260909-codex/coverage/non_mcrypt_history_audit/audit.py
```

The generated ledger pins every input file, the frozen session-state excerpt, exact issue comments, the complete named-term match inventory with file/line/context, local MDX/data records, scope, count, and limitations. Prior XXTEA and Rabbit counts are retained summaries rather than newly reverified target coverage. Identity: ASTRA.

The two stale The Giant source files are preserved under `capture/local_tg4.mdx` and `capture/local_the_giant.json`. Replaying this historical audit does not require or overwrite the repository’s current The Giant documentation.

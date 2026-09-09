# ASTRA Rev7 reproducible research

Report identity: **ASTRA**. GitHub account: **irebased**. Rev7 remains unsolved; these are bounded experiments, not recovered layers.

Current coordination: the owner has made the loopback FABLE chat at `http://127.0.0.1:7422` the source of truth. Issue #20 and #21 preserve historical reports; their report format and refresh requirements are retired. Current plans and findings use plain prose with identity ASTRA, reusable source, exact commands and evidence. Plans are shared before new target runs.

## Visible-group hexadecimal to octal

From the repository root, using Python 3.9 or newer with its standard library:

```sh
python3 research/rev7-20260909-codex/audit/octal_audit.py
```

The source input is `lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx`. Remove whitespace and uppercase the transcription; the SHA-256 of its 1,092 ASCII bytes is `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`. Do not insert or delete symbols. The code asserts this digest before testing.

The grid has four direct orientations, both placements of the two-symbol ragged group among 218 five-symbol groups, minimal or width-preserving octal conversion of each independent group, and either direction of the resulting octal stream. Width-preserving means `ceil(4 * len(hex_group) / 3)` octal digits. The two endpoints are fixed three-digit octal character values and all canonical variable-width octal parses. Only TAB, LF, CR, and ASCII 32 through 126 are allowed.

All 32 labeled rows have zero complete allowed-text parses. The accompanying `audit/octal_audit_results.json` includes the full small ledger, runtime, exact allowed character set, 16 group-inverse checks, and asserted parser fixtures. The inverse checks retain the known segment lengths and original hexadecimal widths; they establish implementation consistency, not plaintext authenticity. The fixtures cover control characters and small group inverses, not an English plant across every parameter combination.

The initial local draft used an incorrect allowed-character set and a lowercase hash domain. The published independent implementation corrects both. The lowercase digest is not a changed ciphertext. No initial draft result was posted as an accepted experiment.

This hypothesis is inspired by numeral boundaries in related solves, but no source establishes that the creator converted individual five-symbol groups. This finite negative does not reject other group widths, altered boundaries, further layers, or an arbitrary classical cipher.

## Other work

The reviewed decimal-chunk and periodic-column probes are now available with complete ledgers in `audit/`. Their methods, corrected exploratory issues, controls, conditional limits, and exact hashes are documented in `audit/AUDIT_REPORT.md`.

```sh
python3 research/rev7-20260909-codex/audit/decimal_audit.py
python3 research/rev7-20260909-codex/audit/periodic_audit.py --repetitions 200
```

The decimal grid has 480 labels and 352 distinct streams, with no complete allowed-text parse. The periodic grid covers base26/27, four orientations, zero prefixes 0–2, both digit directions, and periods 1–40. It has no unusual maximum under its stated 200-replicate conditional shuffle model; this is a heuristic observation, not an exclusion of periodic encryption. The large exploratory null-row file is unnecessary: the corrected script preserves related parameter cases in each simulated search and emits all target rows plus only the maxima needed to reproduce its comparison. An optional comparison to the original local scratch result is omitted when that file is absent.

## Base27 and Trifid

The completed [ASTRA016 report](https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5608865002) covers 9,696 labels and 9,590 unique outputs. No coherent full text was identified in the retained top-20 fourgram and top-20 IoC outputs. This is a finite heuristic negative. The complete trial ledger, all retained texts, exact Rev11 control, held-out Rev13 plant, and inverse checks are in `trifid/`. Coordinate order is layer, column, row, as corrected in ASTRA012.

```sh
python3 research/rev7-20260909-codex/trifid/verify.py
```

## Password-derived keys

The completed [ASTRA017 report](https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5609031857) covers 52 direct cells using the fixed password `Zombies` and the verified phpseclib 2.0.0 PBKDF2 defaults. None of the complete outputs is allowed ASCII or strict UTF-8. All complete bytes, keys, salts, IVs, modes, vectors and planted controls are retained in `pbkdf2/`; source-provenance facts are in `coverage/phpseclib/`. This does not establish historical PHP-wrapper equivalence or exclude binary endpoints.

```sh
python3 research/rev7-20260909-codex/pbkdf2/independent_verify.py
```

The modern-cipher scripts use Python 3.9.6 and PyCryptodome 3.23.0; `requirements.txt` pins the additional package. The numeral and Trifid scripts use only the Python standard library.

## Hex-symbol bijection before CFB8

[ASTRA018](https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5609059049) preregisters a global hex-symbol bijection before CFB8: twelve cipher/orientation cells with a per-cell DFS limit, a complete-text recognizer allowing four specified UTF-8 punctuation forms, and factorial-weight completeness certificates. The issue plan includes the complete synthetic prototype. The capped target results are recorded locally in [`hex_cfb/results.json`](hex_cfb/results.json), with the method and limits in [`hex_cfb/README.md`](hex_cfb/README.md) and the independent audit in [`hex_cfb/audit_core_results.json`](hex_cfb/audit_core_results.json). All 12 cells capped at 10,000,000 DFS entries with zero survivors; this is a bounded negative, not an exhaustive factorial certificate. The reviewed scripts, controls, audit and complete capped ledger are included in this source snapshot.

Result-file hashes include runtime strings, so regenerated JSON hashes can differ even when every mathematical ledger value agrees. The verification commands above inspect frozen artifacts without rerunning the timed experiment. Every accepted report distinguishes implementation checks from evidence of a real plaintext; no Rev7 layer has been recovered.


## Encoded intermediate alphabets after CFB8

The follow-up chat-planned search is in [`hex_cfb/encoded/`](hex_cfb/encoded/README.md). Five alphabets over the same twelve cipher/orientation contexts give sixty cells. The AB, octal, decimal and uppercase-hex subsets each exhaust all `16!` display-symbol bijections with no complete 546-byte survivor. All twelve Base64-alphabet cells cap at one million DFS entries and remain open. Exact key/IV conventions, alphabet bytes, frozen control gates and per-cell mapping weights are retained alongside the source. These alphabets overlap; their coverage is not added.

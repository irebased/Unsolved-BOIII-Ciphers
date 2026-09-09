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


## Whole-integer octal and decimal endpoints

[`whole_numeric/`](whole_numeric/README.md) contains a complete exact parser run: four orientations, whole-integer base8/base10 conversion, either digit direction, then 0–2 prepended zeros, fixed3 or canonical variable2–3 character-code parsing. All 96 cells across 48 distinct streams have zero full parses. The frozen controls include exact leading-zero recovery, reversed-direction inverses and independent short-string parse enumeration. This does not depend on attributing the cipher to a particular historical converter.

## Source routes and frontend inventory

[`sources/primary_routes.md`](sources/primary_routes.md) distinguishes an observed later Revelations depot container listing from missing internal asset names and unverified historical frontend conventions. `sources/t4n_html_inventory.py` reproduces the local form/option/hash inventory for FABLE's three supplied archive bodies; response capture dates and server-side code are not inferred from the requested URLs.


## Historical OFB8 mode controls

`sources/ofb8/` compiles the unchanged OFB mode file from the libmcrypt 2.5.8 mirror import at commit `3bd338e2f808e985f5b229a7642d48c26615993f`. A PyCryptodome ECB callback supplies the block primitive. Twelve AES/Blowfish/DES fixtures over two IV conventions and binary/ASCII data exactly match a separate recurrence and decrypt back through the actual C mode. This isolates mode behavior; it does not reproduce historical key scheduling or frontend handling. No Rev7 input is read. Exact compiler command, type stubs, keys, IVs, plaintexts, ciphertexts, source hashes and upstream license are included.


## Native CFB8 controls

[`hex_cfb/native/`](hex_cfb/native/README.md) contains a synthetic-only C++ implementation of the Base64-alphabet global-map search. The installed OpenSSL 3.6.3 backend accepts the exact seven-byte Blowfish key. AES, Blowfish and DES byte vectors and seeded four-unknown searches match the Python reference; the seeded searches certify all 24 mappings. Full-sixteen-symbol AES controls match every Python counter at 250,000 and 1,000,000 nodes. The latter native run takes about 0.088 seconds on this host (11.4 million nodes/second). Source, frozen controls, compiler command and reproduction instructions are included. These controls make no native Rev7 target claim.


## Native Base64 target completion

The control-gated [native target run](hex_cfb/native/RESULTS.md) exactly reproduces all twelve earlier three-million-node Python prefixes. The six previously capped forward/nibble-swap cells then finish at 13.08–13.88 million nodes each, below the registered 100-million cap. Each cell accounts for all `16! = 20,922,789,888,000` mappings with zero full Base64-alphabet plaintexts. Together with the six previously completed reverse/byte-reverse cells, this exhausts the twelve registered Base64-membership contexts. It does not exclude other keys, IVs, ciphers, modes or binary endpoints. Repeated prefixes are not additive coverage. Source, frozen gate and complete results are in `hex_cfb/native/`.

## Native text endpoint controls

[`hex_cfb/native_text/`](hex_cfb/native_text/README.md) ports the earlier ASCII-plus-four-UTF8-punctuation state machine. Synthetic checks match Python counters, maps and bytes, including seeded exhaustive mixed-punctuation fixtures, rejection of truncated UTF8 endpoints, and capped full-sixteen-symbol prefixes. These control artifacts make no native text target claim.


## Native text target at 100 million nodes

The [native text run](hex_cfb/native_text/RESULTS.md) exactly reproduces all twelve earlier ten-million-node Python prefixes. At the fresh-root 100-million cap, six reverse/byte-reverse cells exhaust all `16!` mappings; the six forward/nibble-swap cells remain capped with incomplete certificates. There are no complete ASCII-plus-registered-UTF8 plaintext survivors. All source, gate hashes and per-cell ledgers are retained; no weight is added across overlapping prefixes.


## Native text target completion

The [final six-cell extension](hex_cfb/native_text/EXTEND_RESULTS.md) exhausts each formerly capped forward/nibble-swap context at 331.9–343.3 million nodes, below its registered one-billion cap. Every certificate is `16!`, with zero terminal plaintexts. All twelve registered AES128/standard-Blowfish/DES CFB8 contexts now exhaust the global hex-bijection model for the stated ASCII-plus-four-UTF8 endpoint. The last six cells took 174.8392 native seconds. `extend_results.json` records the complete counters, engine and input hashes, and prior-ledger gates. Other key, IV, cipher, mode, encoding and binary-endpoint models remain outside this result.

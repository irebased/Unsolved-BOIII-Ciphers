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

The follow-up chat-planned search is in [`hex_cfb/encoded/`](hex_cfb/encoded/README.md). Five alphabets over the same twelve cipher/orientation contexts give sixty cells. The AB, octal, decimal and uppercase-hex subsets each exhaust all `16!` display-symbol bijections with no complete 546-byte survivor. At the initial one-million-node budget all twelve Base64-alphabet cells capped; the later native completion below closes all twelve. Exact key/IV conventions, alphabet bytes, frozen control gates and per-cell mapping weights are retained alongside the source. These alphabets overlap; their coverage is not added.


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

The [native text run](hex_cfb/native_text/RESULTS.md) exactly reproduces all twelve earlier ten-million-node Python prefixes. At the fresh-root 100-million cap, six reverse/byte-reverse cells exhaust all `16!` mappings; the six forward/nibble-swap cells were still capped at that budget, before the completion described below. There are no complete ASCII-plus-registered-UTF8 plaintext survivors. All source, gate hashes and per-cell ledgers are retained; no weight is added across overlapping prefixes.


## Native text target completion

The [final six-cell extension](hex_cfb/native_text/EXTEND_RESULTS.md) exhausts each formerly capped forward/nibble-swap context at 331.9–343.3 million nodes, below its registered one-billion cap. Every certificate is `16!`, with zero terminal plaintexts. All twelve registered AES128/standard-Blowfish/DES CFB8 contexts now exhaust the global hex-bijection model for the stated ASCII-plus-four-UTF8 endpoint. The last six cells took 174.8392 native seconds. `extend_results.json` records the complete counters, engine and input hashes, and prior-ledger gates. Other key, IV, cipher, mode, encoding and binary-endpoint models remain outside this result.


## Fixed-keystream mapping contradictions

[`stream_csp/`](stream_csp/RESULTS.md) exhausts 72 OFB8/full-block-OFB contexts under three fixed cipher/key conventions, three IVs and four orientations. No relaxed-byte or final-FSA survivor remains. An independent verifier recomputes all keystreams using actual historical C OFB8 or library full-block OFB and checks short contradictions. Sixty-eight cells admit no fixed byte assignment for a repeated displayed pair. The other four have zero keystream and fail a distinct-byte count (226 observed versus 104 allowed). These proofs exclude arbitrary global byte permutations within the registered contexts, beyond the original hex-symbol-bijection model. Source, fixtures, gates, full target ledger and independent verification are included.


## Blowfish compatibility semantics and mapping search

[`hex_cfb/native_compat/`](hex_cfb/native_compat/RESULTS.md) verifies the historical libmcrypt Blowfish-compat primitive against 200 supplied WASM vectors and freshly compiled unchanged standard/compatibility C sources. Word-wise byte reversal relates the primitives; the actual raw-seven-byte `Zombies` key is checked, independently of the 16-byte vector keys. The source check includes one block taken from the already-known Rev7 prefix; it is a primitive fixture, not a target decryption/search, and is not described as wholly synthetic. Four registered CFB8 orientations then exhaust every global hex-symbol bijection under the ASCII-zero IV and ASCII-plus-four-UTF8 endpoint. All four certificates equal `16!`, with zero survivors, in 66.16594 native seconds. Source, build helpers, licenses, vector provenance, controls, frozen gate and complete results are included.

## Blowfish compatibility fixed-keystream contradictions

[`stream_csp_compat/`](stream_csp_compat/RESULTS.md) adds 24 contexts: historical OFB8/full-block OFB, three IV conventions and four orientations, using the raw-seven-byte `Zombies` key and verified compatibility primitive. All 24 are unsatisfiable at root propagation and each has a short repeated-pair witness that directly rules out every mapped byte from 0 through 255. Thus these witnesses exclude every fixed global byte mapping, even nonbijective, within the stated cipher/key/IV/endpoint contexts. The accompanying source and result ledger separate these byte witnesses from the complete `16!` hex-bijection certificates.

## PHP API key handling

[`sources/php_mcrypt_api/`](sources/php_mcrypt_api/REPORT.md) records the actual official PHP 5.4.45 and 5.6.25 `mcrypt_encrypt` source paths. For the seven-byte key, the older implementation pads Rijndael-128 to 16 bytes and DES to 8 while retaining raw-seven-byte Blowfish; the newer implementation rejects unsupported AES/DES key lengths while accepting raw-seven-byte Blowfish. This is a source audit with explicit transcribed decision cases, not a PHP runtime test or identification of the original website's server version. Exact snapshots, hashes, numbered excerpts, source links and licenses are included.


## Original-source sibling chain controls

[`hex_cfb/native_siblings/`](hex_cfb/native_siblings/README.md) supplies unchanged pinned RC2 and Loki97 C modules, minimal build headers, native/Python CFB8 and DFS controls, and a complete solved Rev5 replay. Every cipher layer re-encrypts exactly. A separate input-pinned replay matches the stored stage ledger; the only normalized JSON plaintext difference is a recovered curly apostrophe versus the editorial straight apostrophe. The accompanying [library key-memory audit](hex_cfb/native_siblings/LIBRARY_KEY_MEMORY.md) shows that libmcrypt allocates a zero-filled buffer at the algorithm maximum key size, explaining Loki97's 32-byte backing buffer while passing a selected length of 16. These are controls only, with no Rev7 target run.

## Recovered sibling ellipsis and endpoint boundary

The [recorded Unicode inventory](sources/sibling_unicode/REPORT.md) distinguishes JSON plaintext from MDX blockquotes and identifies an ellipsis in Rev9. The [original-source Rev9 replay](sources/rev9_source/README.md) confirms that this is present in actual decrypted bytes: `E2 80 A6` at offset 134. Its 149-byte plaintext matches the complete record plus a final newline, and both DES and Twofish layers re-encrypt exactly. The existing four-punctuation Rev7 exclusions remain finite results for their stated endpoint; they do not cover this fifth sequence. The five-sequence controls and the expanded OFB proof are documented below; the earlier endpoint remains explicitly distinguished.

## Byte-column permutation certificates

The [byte-column target report](../byte_columnar/RESULTS.md) exhausts widths 13 and 14, both defined variants A/B, and all four canonical orientations under AES-128 CFB8, `Zombies` plus nine NUL bytes, an ASCII-zero IV, and the strict five-punctuation endpoint. All sixteen cells finish uncapped with zero survivors; each certificate equals its own `13!` or `14!`. Total reported native time is 1.461436632 seconds. The source includes exact transform definitions, independent small exhaustive comparisons, FABLE function fixtures, 546-byte planted recoveries, random controls, cap accounting, frozen gates, and the complete target ledger. This scope excludes neither other ciphers nor other widths. The original README is a frozen controls-stage document; the later TARGET and RESULTS files record the subsequent target work.

## OFB contradictions with the recovered ellipsis admitted

The [expanded witness report](sources/ellipsis_witness/EXTENDED_REPORT.md) reconstructs and hash-matches all previously tested OFB streams, then admits `A6` into the necessary relaxed plaintext byte set. Twenty old short witnesses lose their contradiction, but all 92 relevant contexts have regenerated repeated-pair witnesses that reject every possible mapped byte. The four remaining Blowfish/OFB8/NUL contexts are independently rechecked as zero keystream with 226 distinct displayed bytes versus 105 allowed plaintext bytes. All 96 prior contexts therefore remain excluded for the expanded endpoint. The compatibility block implementation relies on the previously independently verified helper; this extension does not claim another independent cipher implementation. The compact ledger preserves full context, positions, keystream bytes, and one contradiction per cell; it also records the 1,650 total contradictory repeated pairs found.

```sh
python3 -B research/rev7-20260909-codex/sources/ellipsis_witness/extend.py
```

## Five-punctuation CFB8 mapping completion

The [expanded native text result](hex_cfb/native_text5/RESULTS.md) completes all sixteen AES-128, standard Blowfish, DES, and Blowfish-compat orientation cells under their registered `Zombies` keys and ASCII-zero IVs. Each accounts for all `16!` global hex-symbol bijections with zero plaintext survivors and zero uncovered weight. Total native time was 223.31039 seconds. The endpoint is ASCII plus exactly five complete UTF-8 punctuation sequences, including the recovered Rev9 ellipsis; terminal state must be zero. Synthetic controls, unchanged historical source modules and licenses, build headers, frozen gate, driver, and full target ledger are included. RC2 and Loki97 have controls in the same engine but were not target-tested in this run. The README preserves the earlier controls-only snapshot; RESULTS records the subsequent run.

## IV-independent CFB window geometry

The [geometry measurement](iv_independent/REPORT.md) records which displayed symbols must be assigned before a CFB8 plaintext byte after the first block can be evaluated without knowing an IV. With 8-byte blocks, the minimum nine-byte window uses seven different hex symbols, requiring `P(16,7) = 57,657,600` assignments. With 16-byte blocks, the minimum is twelve symbols and `P(16,12) = 871,782,912,000`. These are structural target measurements without decryption or key evaluation. The complete window ledger is deterministically regenerated by `geometry.py`; the compact publication summary retains histograms, all minimizers, chosen anchors, and greedy constraint counts. No IV-independent target exclusion or recovered plaintext is claimed by this geometry result.

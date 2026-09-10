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

## Every-IV byte-column contradictions

The [stronger byte-column report](../byte_columnar/all_iv/RESULTS_STRONGER.md) rules out the eight AES/variant-B width13/14 orientation contexts for every external 16-byte IV. Every observed column is an unavoidable contiguous ciphertext chunk under some natural-column label. Its CFB8 plaintext suffix after the first 16 chunk bytes depends only on the chunk, so one invalid suffix rules out every column order and every IV. All 108 chunks reject here. Complete chunk and suffix bytes, first failing FSA states, independent library checks, small exhaustive planted controls, exact gates, and a standalone witness verifier are included. This result keeps the fixed key, cipher, variant, width and endpoint limits; the completed ragged-width extension is documented below.

```sh
python3 -B research/byte_columnar/all_iv/verify_stronger_results.py
```

## IV-independent DES mapping completion

The [DES solver controls](iv_independent/solver/NATIVE_README.md) validate a new mapping search over ciphertext-only CFB8 windows after the first eight bytes. Python optimized and all-bound-window reference paths agree with seeded naive enumeration; native controls match all counters and suffixes at seeded exhaustive and full-map capped prefixes. Mode, block-cipher, UTF-8 boundary and cap checks are retained. The [ordering cost audit](iv_independent/ORDER_COST.md) uses a declared heuristic model, with a 512-state dynamic program and a 9! brute-force comparison; it finds no improvement over the existing greedy remaining-symbol order. This model predicts cost, not plaintext likelihood or completion.

`iv_independent/solver/target_gate.json` and `run_target.py` register four DES orientation cells, the fixed `Zombies`+NUL key, every external eight-byte IV through IV-independent suffix constraints, all global hex-symbol bijections, and a fresh one-billion-node cap per cell. The first eight plaintext bytes are unconstrained. The [completed target report](iv_independent/solver/RESULTS.md) accounts for all `16!` mappings in every orientation with zero survivors, zero capped cells and zero unaccounted weight. The run used 1,183,144,700 DFS entries and 10,825,700,904 DES ECB calls in 747.73 seconds. These suffix contradictions exclude every external IV under the fixed key, representation and endpoint model; no IV or plaintext was recovered. Root verification checked the frozen source/gate hashes, orientation hashes, geometry and final accounting without repeating the search.


## Ragged byte-column contradictions for every IV

The [ragged AES report](../byte_columnar/all_iv/ragged/RESULTS.md) extends the variant-B proof to widths 2 through 32 under both first-long and last-long column conventions. For `546 = q*w + r`, the first `q` complete observed rows expose the guaranteed contiguous prefix `observed[rank:q*w:w]` of each natural ciphertext chunk. The compressed ragged tail is ignored. Every width/orientation case has at least one prefix whose IV-independent CFB8 suffix fails the endpoint from all possible boundary states. All 124 cells close; eight repeat the earlier width13/14 result exactly and 116 are new. The source and full ledger retain all 132 examined prefixes, suffixes, first failures, two-IV library checks and per-convention factorial certificates. Convention weights are not added, and are aliases in the rectangular cases.

The fixed cipher is AES-128 with `Zombies` plus nine NUL bytes and the same five-punctuation endpoint. The proof covers every external 16-byte IV and every order in each registered column convention. It does not cover variant A, widths above 32, other keys, modes, framing beyond the raw-IV-prefix corollary below, or broader endpoints. The registered driver and synthetic controls are included; this result is a finite exclusion and does not recover a Rev7 layer.


## Minimum byte corrections under fixed OFB streams

The [stream robustness audit](stream_robustness/REPORT.md) computes a necessary lower bound on same-length ciphertext-byte corrections after selecting a fixed mapping for displayed byte pairs. For each pair class, it tests all 256 mapped bytes and sums the minimum number of outputs outside the relaxed 105-byte endpoint. The 92 nonzero-stream contexts require 14 through 26 corrections even when the mapping may be nonbijective. In the four zero-keystream contexts, arbitrary maps can collapse every class to one allowed byte; requiring an injective byte map instead gives an exact relaxed-alphabet bound of 179 invalid positions, because only 105 of the 226 observed classes can map to allowed bytes. These are separate mapping models and their bounds are not added.

All 96 streams match their frozen prior hashes. The arithmetic verifier independently rebuilds canonical orientations and pair positions, matches exact context identities and stream hashes, recomputes histogram optima and constructive maps, and checks the compact summary. It does not reimplement the block ciphers. Source, computed controls and the compact context ledger are included; the full pair ledger is regenerated locally using the documented commands. This audit adds no keys, IVs or modes, and does not cover insertions, deletions or CFB.


## Eight-byte-block ragged column completion

The [DES and Blowfish column result](../byte_columnar/all_iv/ragged8/RESULTS.md) closes all 708 registered cases: DES, standard Blowfish and historical Blowfish-compat, each with its stated `Zombies` key convention, widths 2 through 60, four canonical orientations, both ragged conventions and every external eight-byte IV. All use CFB8 and the five-punctuation endpoint. The 767 examined prefixes include a rejecting unavoidable chunk in every case; each case certifies all `w!` orders separately per convention. These certificates overlap and their weights are not added. The result leaves zero unresolved cases within the registered scope and recovers no plaintext.

The published compact JSON retains every field from the full ledger. A [portable read-only verifier](../byte_columnar/all_iv/ragged8/verify_results.py) checks all 708 cases and 767 chunks using PyCryptodome, including the independently established Blowfish-compat word-reversal relation; it requires no compiled binary. It also reconstructs the pretty JSON in memory and verifies the original full-ledger SHA-256. The original README and gate describe the earlier unrun control stage; RESULTS records the completed target. Local drafts and binaries are excluded from publication.

```sh
python3 -B research/byte_columnar/all_iv/ragged8/verify_results.py
```

## Exact raw-IV-prefix framing corollary

The [raw-IV-prefix proof](iv_independent/raw_iv_prefix/README.md) applies when the same 546-byte decoded stream is interpreted as `S = IV || C`, with exactly one raw block IV at its start and the tested mapping or column transform acting on the entire frame. No bytes are added. For each frame index `i >= b`, actual payload plaintext is `P[i-b] = S[i] XOR E_key(S[i-b:i])[0]`. A guaranteed natural chunk beginning at frame offset `a` therefore has exactly payload slice `P[a:a+q-b]` as its local IV-independent suffix. The existing necessary suffix contradictions transfer unchanged, including the DES global-hex result; no target rerun is required.

This covers payload lengths 530 for AES and 538 for eight-byte primitives within the corresponding already-tested keys, orientations, widths and representation models. The payload must satisfy the registered endpoint. It does not generalize to extra headers, encoded IV strings, an IV outside the transformed region or trailing framing. The accompanying synthetic controls check mode encryption/decryption, whole-frame recurrence, exact chunk-to-payload indexing and UTF-8 boundaries. This is an interpretation of existing certificates, not additive target coverage.


## Minimum span of one OFB corruption region

The [interval result](stream_robustness/interval/RESULTS.md) finds the shortest contiguous decoded-byte region that can be ignored while the remaining positions fit an arbitrary fixed displayed-pair map under each of the same 96 OFB streams. The 92 nonzero-stream cases have minimum spans of 163 through 292 bytes, with exactly one minimizing interval per case. The four zero streams allow span zero under arbitrary maps; this does not imply an injective solution. These are spans, not counts of changed bytes.

A two-pointer solver is checked by a separate per-class prefix/suffix-mask certificate: every interval at length `L-1` is infeasible, every interval at `L` is enumerated, and a representative fixed map is validated at every outside position. Monotonicity rules out all shorter lengths. The full ledger preserves every minimizing interval and all check counts; the scripts and synthetic exhaustive controls are included. These positive lower bounds remain necessary under bijective mapping restrictions, while the exact stricter optima were not computed.

For the 92 nonzero contexts, the lower bound also excludes corruption confined to any 128 consecutive displayed hex symbols, which can touch at most 65 decoded-byte positions. The four zero streams are excluded under an injective map by the separate 179-position correction-count bound. This conclusion stays within the registered keys, IVs, OFB modes, byte-pair mappings and unchanged alignment; it does not extend to CFB, other streams or multiple separated damage regions.


## Ordered-chunk adjacency certificates

The [adjacency result](../byte_columnar/all_iv/adjacency/RESULTS.md) closes all 32 registered rectangular variant-B cases: AES-128 widths 39 and 42, and DES, standard Blowfish and historical Blowfish-compat widths 78 and 91, each across four canonical orientations. The fixed Zombies keys, CFB8 mode, every external block-size IV and five-sequence endpoint are retained. In this geometry, an individual chunk is too short to expose an IV-independent suffix, but two adjacent chunks expose one. Any valid column order must therefore form a Hamiltonian path through the graph of locally admissible ordered pairs.

All 32 graphs have at least two zero-indegree vertices, so none admits such a path. The completed run examined 183,168 ordered pairs; the sufficient certificates retain 4,640 incoming bad-edge witnesses. Each case excludes all `w!` orders without a Hamiltonian search. No plaintext was recovered. Other widths, ragged layouts, variant A, keys, ciphers, modes and endpoints remain outside this result.

The [193,082-byte certificate package](../byte_columnar/all_iv/adjacency/certificate_package.json) preserves all graph and result metadata and losslessly reconstructs the full 3,682,489-byte ledger, SHA-256 `d208d2a06218faf16e5caa16bbf13585e39ac7e82b395528e76c20140ec2a6e7`. Source, synthetic controls, frozen gate, packing code and portable verifier are included. Default verification replays only the sufficient witnesses; optional full-pair verification separately matches every graph digest and retained edge. Both verification modes passed and require PyCryptodome without compiled compatibility binaries.

```sh
python3 -B research/byte_columnar/all_iv/adjacency/pack_results.py --verify
python3 -B research/byte_columnar/all_iv/adjacency/verify_results.py
python3 -B research/byte_columnar/all_iv/adjacency/verify_results.py --full-pairs
```


## Column-A every-IV proof and synthetic controls

The [column-A proof package](../byte_columnar/all_iv/column_a/README.md) establishes a separate necessary constraint for rectangular column permutations. FABLE's `order[rank]` identifies the natural column, so reconstruction uses its inverse `slots`: `C[row*w+j] = observed[slots[j]*q+row]`. With an eight-byte CFB block and width greater than eight, ciphertext columns zero through seven determine the plaintext byte at column eight independently of the IV. For each distinct first-eight rank tuple, the reference intersects all possible ninth-column ranks across rows using the relaxed 105-byte alphabet. An empty mask excludes all `(w-8)!` completions; surviving prefixes remain unresolved.

The controls compare the exact vendored FABLE transform, twenty small full-permutation cases including explicit positive and negative controls, and six DES, Blowfish and historical Blowfish-compat plants under two IVs each. Every true ninth rank is uniquely retained in the real-cipher plants. Historical C compatibility source, build shims, LGPL license and provenance are included; regeneration compiles in a temporary directory and compares that source against a separate PyCryptodome word-reversal implementation. The default command checks the frozen ledger and source identity without writing; explicit regeneration requires a new output path.

```sh
python3 -B research/byte_columnar/all_iv/column_a/controls.py
python3 -B research/byte_columnar/all_iv/column_a/controls.py --regenerate /tmp/column-a-controls.json
```

This is a proof and synthetic-control package only. It contains no Rev7 target evaluation and recovers no order, IV or plaintext. The alphabet is a relaxed necessary byte filter, not a strict UTF-8 parser. Native implementation and any later target evaluation are separate artifacts.


## Blowfish every-IV mapping solver controls

The [native Blowfish control report](iv_independent/blowfish_solver/REPORT.md) adapts the completed DES mapping engine to standard Blowfish and the established historical word-conjugated compatibility primitive, each with raw seven-byte `Zombies`. The search preserves the IV-independent ciphertext-window constraints, global hex-symbol bijection, factorial accounting, caps, and strict five-sequence suffix endpoint. The suffix starts in any UTF-8 boundary state and must end in state zero; no first-block plaintext or IV recovery is claimed.

The accepted controls check 64 block vectors, four independent 546-byte CFB8 plants under two IVs per cipher, and eight complete native searches against a separate exhaustive 4! reference. Exact mapping and suffix sets agree in all cases. Four planted mappings are recovered, two random and two prebound cases reject, and two cap-one controls preserve explicit incomplete accounting. Historical compatibility C is built temporarily and checked against both native OpenSSL and separate PyCryptodome conjugation. Default verification is read-only; regeneration requires a new output path and records compiler/source provenance.

```sh
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.py
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.py --regenerate /tmp/bf-solver-controls.json
```

This publication is synthetic evidence only and contains no Blowfish every-IV Rev7 target evaluation. The initial incomplete helper and weak controls were rejected and are excluded from publication. Only the accepted native search, independent controls, ledger and report are included.


## Frozen column-A native experiment

The [native column-A controls](../byte_columnar/all_iv/column_a/native/REPORT.md) validate the prefix search against complete Python width-nine enumeration for all three backends, preserving 4,223 DES, 4,352 Blowfish and 4,175 compatibility prefixes. Wider bounded controls compare exact prefixes and masks at widths 10, 13 and 14, deliberately including multiple surviving candidate ranks. Ninety-six block vectors and three full CFB8 vectors match independent references. A source-built historical compatibility implementation is checked before its established conjugation is used for larger reference scans. Source and default read-only verification are portable; compilation and full regeneration are explicit.

The [registered target driver](../byte_columnar/all_iv/column_a/target/README.md) freezes 24 cases: the three eight-byte ciphers, widths 13/14, four canonical orientations, fixed Zombies keys, CFB8, every external IV, and the relaxed A105 necessary constraint. Each case will examine all first-eight rank tuples; the total workload is 2,075,673,600 tuples. Completed and unexamined weights must account for every full order, and every retained prefix/mask is independently replayed. A cell closes only if a complete scan retains no prefixes. The gate SHA-256 is `81563be8c6c2c8b87c6afa2ec733d6e476a196bc6c5002dfce6c33cb8902021b`; source, controls, gate builder and driver passed review before freezing.

```sh
python3 -S -B research/byte_columnar/all_iv/column_a/native/native_controls.py
python3 -B research/byte_columnar/all_iv/column_a/target/run_target.py --selftest
```

At this publication stage the target is registered and unrun. No target result or recovered layer is claimed. The gate binds the tested local binary hash; binaries and drafts are excluded from publication, while source and build commands are included.


## Frozen every-IV Blowfish mapping experiment

The [registered Blowfish target](iv_independent/blowfish_solver/target/README.md) adds an eight-case specification for standard Blowfish and historical compatibility Blowfish under four canonical orientations, raw seven-byte Zombies keys, CFB8, every external eight-byte IV, and global hexadecimal-symbol bijections. Each case starts from an unseeded root with a one-billion-node cap. Complete coverage accounts for all `16!` mappings; capped cases retain their explicit uncovered remainder. Exact surviving maps and suffix bytes receive independent reconstruction, strict FSA validation and two-IV re-encryption checks.

A bounded synthetic benchmark completed one million nodes per backend at roughly 2.3 million nodes per second. A linear projection gives about seven minutes per full cap, or roughly 58 minutes for all eight sequential caps; actual target traversal and host contention can differ. This is a runtime estimate and does not establish target coverage. Source, build provenance, independent controls, benchmark, gate builder and driver are published. The final gate SHA-256 is `507f5c9d3f0a489ca612bfaf1600c9c3de91f844208540962b8a087274204a2b`.

```sh
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/benchmark.py
python3 -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/run_target.py --selftest
```

At this publication stage the Blowfish target is registered and unrun. Its controls and preparation code read no target ciphertext beyond hashing the canonical MDX during gate checks. The deliberately unusable draft gate and superseded documentation gate are excluded from publication.


## Completed column-A every-IV search

The [completed column-A result](../byte_columnar/all_iv/column_a/target/RESULTS.md) closes all 24 frozen cases with no surviving first-eight tuple or ninth-column candidate. The controlled native search examined and rejected all 2,075,673,600 prefixes in 450.13858 native seconds, using 6,607,624,222 block calls and 20,058,449,558 candidate tests. Each width-13 cell accounts for every 13! order, and each width-14 cell accounts for every 14! order. No case is capped or unresolved.

This excludes the registered rectangular variant-A column orders for DES, standard Blowfish and historical Blowfish-compat, fixed Zombies key conventions, widths 13/14, four canonical orientations, CFB8 and every external eight-byte IV under the relaxed A105 necessary byte condition. It does not recover plaintext or an IV and does not extend to other widths, keys, ciphers, modes, endpoints or layouts.

The [45,574-byte result ledger](../byte_columnar/all_iv/column_a/target/target_results.json), SHA-256 `7ecf4315867eb5cb9ebaa8b3a907fdb476245520ea0f4115063d0c9addb85617`, preserves all 24 cells and their exact accounting. Root verification checked the frozen source/gate identities, canonical orientations, exact cell set, completion weights and equality with local atomic cell files. A portable standard-library verifier is included. This is integrity and accounting verification of a controlled native run, not a second independent 2.075-billion-prefix search.

```sh
python3 -S -B research/byte_columnar/all_iv/column_a/target/verify_results.py
```


## Completed every-IV Blowfish mapping search

The [completed Blowfish result](iv_independent/blowfish_solver/target/RESULTS.md) closes all eight registered cases: standard Blowfish and historical Blowfish-compat, raw seven-byte Zombies, CFB8, four canonical orientations, and every external eight-byte IV under a fixed global bijection of the 16 displayed hex symbols. Each cell exhausts its full `16! = 20,922,789,888,000` mapping weight, with zero survivors and no uncovered remainder. None reached its fresh one-billion-node cap. The IV-independent suffix uses the necessary A105 filter and the registered strict five-sequence FSA endpoint. Other keys, modes, mappings, transforms and endpoint assumptions remain outside this result.

The single uninterrupted invocation entered 2,365,440,332 DFS nodes and made 21,643,489,230 block calls in 1,130.035 native seconds. The [17,208-byte ledger](iv_independent/blowfish_solver/target/target_results.json), SHA-256 `dffebff216727736c2b21b58a3dfc75576b7798375603a0d6bc8ee67338d83fc`, retains every cell and its exact certificate accounting. Source-backed synthetic controls and the frozen preregistration were published before execution.

Root checked all local frozen sources and result invariants. The published standard-library verifier checks source provenance, canonical orientation hashes, deterministic search geometry and stored accounting without requiring the excluded executable. It compares the recorded binary hash to frozen build provenance; `--check-local-binary` optionally checks an available local executable. This is integrity and accounting verification, not a second independent 2.365-billion-node search.

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/blowfish_solver/target/verify_results.py
```


## CFB8 cascade proof and interval controls

The [direct cascade proof](iv_independent/cascade/README.md) extends IV forgetting to multiple same-length binary CFB8 layers with fixed known keys. In outer-to-inner decryption order, a final plaintext suffix starting at the sum of the block sizes is determined by the outer ciphertext without knowing any layer's IV. Intermediate bytes need not be printable. Five mixed AES/DES/Blowfish/ARC2 chains have 40 synthetic vectors and 80 independent full MODE_CFB versus ECB-window comparisons, including length boundaries and partial UTF-8 starts.

The [known-interval extension](iv_independent/cascade/INTERVAL_EXTENSION.md) separately covers the four canonical byte transforms between layers. A known input interval `[L,R)` becomes `[min(L+b,R),R)` after CFB8; byte reversal relocates it to `[N-R,N-L)`, and nibble swap preserves its positions. Four two-layer recipes and all 16 ordered transform pairs in the three-layer recipe produce 168 controls. Sixty-eight fixtures exercise UTF-8 splits at the exposed edges. Forty empty intervals remain explicitly inconclusive. Every vector also holds the outer ciphertext fixed and changes all IVs, confirming equal interval bytes despite different outside bytes.

Root reviewed the proof and independently regenerated both complete synthetic ledgers, matching their exact contents and hashes: direct `2b0b75c096da6e3333dfe3d7390cb1d8a458d551d895ab215401c32155408b87`, interval `43b7f352f14cc87b1c0452338334f9dbde3db74abdfd16dab2ff726adb269037`. Default commands check source identity and recorded control metadata with the standard library; explicit regeneration performs the cryptographic comparisons with PyCryptodome and requires a new output path.

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/proof.py
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/interval_extension.py
python3 -B research/rev7-20260909-codex/iv_independent/cascade/interval_extension.py --regenerate /tmp/cascade-interval-controls.json
```

This package contains no Rev7 target search. It covers aligned same-length binary layers and the stated involutions; encodings, transpositions, framing and padding changes require separate reasoning. It does not recover bytes outside the proved interval. The underlying CFB recurrence is specified in [NIST SP 800-38A, section 6.3](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf); the cascade/interval consequences here follow by composition of those dependencies.


## Source-backed RC2 column-A controls

The [RC2 control package](../byte_columnar/all_iv/column_a_rc2/REPORT.md) adapts the accepted rectangular variant-A prefix engine to unchanged historical RC2 C source, raw seven-byte Zombies and the effective 1024-bit schedule. The search logic is unchanged; the wrapper uses aligned 16-bit block storage. The historical KAT, 128 independent PyCryptodome block comparisons and two complete 256-byte CFB8 streams pass. Two complete width-nine planted scans retain 4,154 and 4,279 prefixes and match every Python prefix/mask and counter. Bounded width-10/13/14 controls include multiple ninth-rank candidates and preserve exact unexamined factorial weights.

Root regenerated the entire synthetic package in a separate temporary directory. All deterministic result fields matched; only timing-derived fields and the temporary shared-library machine hash differed. The native executable hash reproduced exactly as `679844dc071cce779d86667f1b8e55c5175045840d7b47044312f28dfdfd4b3b`. The accepted ledger SHA-256 is `7330bad3670745ef659dd597a3385ee06b7225b17eadb997a0e80519ac3abb9f`. One-million-prefix synthetic benchmarks project approximately 15.78 seconds for width 13 and 38.99 seconds for width 14 per orientation, about 219 seconds for a prospective eight-case grid. Those are fixture/host estimates, not target coverage.

```sh
python3 -S -B research/byte_columnar/all_iv/column_a_rc2/controls.py
python3 -B research/byte_columnar/all_iv/column_a_rc2/controls.py --regenerate /tmp/rc2-column-a-controls.json
```

This publication contains source, license, shims, controls and reports only. No RC2 column-A target driver, gate, evaluation or recovered layer is included.


## Saved texture transcription check

The [texture audit](texture_audit/README.md) compares all 16 rows of the saved Rev7 image against the canonical 1,092-symbol transcript. Raw Apple Vision OCR and the exact Swift/Python source are included. After explicit non-hex OCR normalization, three valid-hex machine differences remain at zero-based offsets 276, 366 and 595: OCR reads 4 where the transcript records A. Visual review supports the existing A in groups 6272A, 2D87A and 6B9A4. The raw differences remain preserved for independent inspection. No discrepancy was found in this saved texture, and the canonical MDX and target bytes are unchanged.

The comparison uses the saved repository image, SHA-256 `36a1883ede6abadcf4d4420f26484ca81134f3b62fe0ac7521352c682bf0b3b7`, rather than a newly acquired game asset. Replaying the comparison requires only Python's standard library; fresh OCR requires macOS Swift and Apple Vision. No external OCR service or image modification was used.

```sh
python3 -S -B research/rev7-20260909-codex/texture_audit/compare.py
```


## Frozen RC2 column-A target

The [registered RC2 target](../byte_columnar/all_iv/column_a_rc2/target/README.md) freezes eight cases: historical RC2 with raw seven-byte Zombies, widths 13/14, four canonical orientations, rectangular variant A, CFB8, every external eight-byte IV, and the necessary A105 ninth-column constraint. The exact workload is 691,891,200 first-eight tuples. Every survivor prefix/mask is retained and independently replayed through ARC2 effective-keylen 1024; each case closes only after complete zero-survivor enumeration.

The gate SHA-256 is `191240f56bcdea2233fece19cfa5f429c4296463f2a081bba8899152b4de642b`, and the reviewed driver SHA-256 is `deea54124124bae750ba57a35ebed6c5770e4f861ed25ae3aed6a7c660b1ab9a`. Source, controls, docs, build helper and gate builder are bound by hashes. A target invocation temporarily compiles the historical source and requires exact agreement with the object/executable hashes independently reproduced during controls. Preparation selftest passed while hashing the MDX only.

```sh
python3 -S -B research/byte_columnar/all_iv/column_a_rc2/target/run_target.py --selftest
```

This snapshot registers an unrun experiment. Execution follows a separate FABLE preregistration and root GO; no target result or plaintext is included here. Existing outputs are refused, and each result cell is written atomically.


## Completed RC2 column-A every-IV search

The [completed RC2 result](../byte_columnar/all_iv/column_a_rc2/target/RESULTS.md) closes all eight preregistered cases with zero survivors and no unexamined weight. The controlled native enumerator examined and rejected all 691,891,200 first-eight prefixes in 221.8278 native seconds, recording 2,202,549,490 block calls and 6,686,103,593 ninth-rank candidate tests. Each width-13 cell accounts for all 13! orders, and each width-14 cell for all 14! orders; these per-orientation spaces are not additive evidence.

The exclusion is limited to historical RC2, raw seven-byte Zombies with the effective 1024-bit schedule, CFB8, rectangular FABLE columnar A at widths 13/14, four canonical orientations, every external eight-byte IV, and the relaxed A105 necessary endpoint condition. No plaintext or IV was recovered.

The [21,605-byte ledger](../byte_columnar/all_iv/column_a_rc2/target/target_results.json), SHA-256 `8c8b94ed9def1daacfc04e25aa03f4c25a89568ab29072a6672c49dde766e9de`, preserves all eight results. Root replayed the portable verifier under Python's standard library, including equality against every local atomic cell. It checks frozen source/control/gate/build identities, canonical orientations, exact cell identifiers, factorial completion weights and recorded aggregates. This is integrity and accounting verification, not a second enumeration. With no survivors, the independent target ARC2 candidate replay had no masks to evaluate.

```sh
python3 -S -B research/byte_columnar/all_iv/column_a_rc2/target/verify_results.py
```


## Seven-backend binary cascade runtime

The [synthetic runtime package](iv_independent/cascade/runtime/README.md) supplies scheduled block, CFB8 and known-interval decryption for AES-128, DES, standard Blowfish, historical Blowfish compatibility, RC2, Twofish and Loki97 under the fixed solved-family Zombies conventions. Exact historical C sources, minimal build shims, provenance and licenses are included. Source-backed libraries are compiled only in a temporary directory and are excluded from publication.

The [runtime ledger](iv_independent/cascade/runtime/controls.json), SHA-256 `483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5`, records historical KATs, 32 independent compatibility block comparisons, seven complete byte-value CFB8 vectors, 35 interval boundaries and a seven-layer cascade under two unrelated IV suites. Standard backends use independent MODE_CFB and ECB-window references. Twofish and Loki97 match frozen prior source-control streams; those do not constitute independent second implementations of the primitives.

Root reviewed the source and independently regenerated the full synthetic package. All deterministic fields matched. Differences were confined to benchmark timings/rates/projections and temporary library paths/build hashes. The default verifier checks source and structural integrity using the standard library; actual cryptographic regeneration requires PyCryptodome and clang. No Rev7 target was read or evaluated by this control package.

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.py
python3 -B research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.py --regenerate /tmp/cascade-runtime-controls.json
```

This snapshot provides controls only. A future cascade target needs its own reviewed traversal, endpoint controls and frozen registration.


## Controlled cascade traversal before target registration

The [cascade driver and controls](iv_independent/cascade/target/README.md) prepare 22,764 CFB8 path endpoints across seven fixed-key backends, depths one to three, four outer orientations and four interlayer involutions. Nontext intermediate nodes continue to expand. Endpoint checks apply the A105 necessary byte filter and boundary-aware five-sequence UTF-8 FSA to each proved known interval.

Seven direct synthetic plants, a two-layer plant with a rejected intermediate and retained child, and a mixed three-layer plant all recover their known plaintext intervals and re-encrypt exactly under two independent IV suites. A branching control exercises 584 endpoints across four orientations and all interlayer transforms. Every interval matches full-reference decryption; every classification matches a separate endpoint oracle. Exact ID accounting passes, with 583 rejected endpoints and the one intended retained leaf. Its deterministic row digest is `0e6444288f89d7d689bd465470429a5117830b8e3e18c7b655ca980b859cfcf9`.

Root reviewed the complete source and regenerated the full [control ledger](iv_independent/cascade/target/controls.json), SHA-256 `0cdf349df9657818394991daf9e0c753b1e4b7c8a1aaa52a1dd43bb6f4ecd0c4`. All deterministic fields matched; only the three temporary library hashes differed. The frozen driver SHA-256 is `dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41`. Source, controls and the inert gate helper are included; this snapshot has no target gate or evaluation.

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/controls.py
python3 -B research/rev7-20260909-codex/iv_independent/cascade/target/controls.py --regenerate-dir /tmp/cascade-target-controls-new
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/run_target.py --selftest
```

The default control command verifies source and structural integrity; regeneration performs the synthetic cryptographic comparisons. The target requires a separately published gate following FABLE preregistration and root GO. Existing output/checkpoint files are refused; there is no resume mode.


## Frozen cascade gate and independent endpoint audit

Following FABLE message 139, the [cascade gate](iv_independent/cascade/target/target_gate.json) freezes the previously published driver, all runtime/proof/prior-source controls, target controls, gate builder, documentation, canonical MDX and exact 22,764-path scope. Its SHA-256 is `80471b6c6de67bfa07370a5b18c0a024200f6a6b7b5617df79bc5562d9605620`. Root ran the hash-only driver selftest with this gate present; all artifact identities and exact path counts passed. This snapshot still precedes target execution.

An additional [endpoint audit](iv_independent/cascade/endpoint_audit/REPORT.md) compares the frozen target driver's FSA against a separately expressed regular-expression completion oracle. All 354,960 nonempty representative-byte cases match across four boundary modes. Empty intervals remain explicitly inconclusive. Root reran the full synthetic audit and reproduced the exact ledger SHA-256 `4727046f73b5de38c49f14619603269b20d30261d2534fb653278531312151c4`. It tests the current target driver, uses valid interval coordinates, reads no Rev7 bytes and performs no cryptography. The finite category suite does not prove acceptance for arbitrary byte strings.

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/endpoint_audit/endpoint_audit.py --verify research/rev7-20260909-codex/iv_independent/cascade/endpoint_audit/endpoint_audit.json
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/endpoint_audit/endpoint_audit.py --output /tmp/cascade-endpoint-audit-new.json
```


## Byte-unit AMSCO geometry and composition controls

The [byte-AMSCO package](../byte_amsco/astra/README.md) defines continuous alternating one/two-byte cells, row-major placement, arbitrary column read order, and exact inversion with shortened final cells. It is a binary analogue before hex serialization; historical PHP AMSCO operates on characters. These are distinct pipeline hypotheses.

Independent production forward/inverse implementations and separate tuple-token oracles agree on 37,012 exhaustive small fixtures. Length-546 controls cover widths 2 through 9 and both starts. Seven accepted CFB8 backends pass all four orientations and two arbitrary-IV plants, with exact pre-transposition ciphertext recovery and the expected IV-independent suffix. Root independently regenerated the entire [control ledger](../byte_amsco/astra/controls.json), SHA-256 `767d651729055d1d6fa202e8983635d3afafd46d06729924569db7260ed21175`. All deterministic fields matched; differences were limited to temporary source-build paths/hashes and benchmark timing fields.

The prospective geometry grid is 3,272,896 transforms. A bounded 50,000-order baseline estimates approximately 262 seconds for Python geometry alone; it excludes cipher and endpoint work. A future target should precompute metadata and gather only required windows before early rejection. This package contains no target driver, gate or evaluation.

```sh
python3 -S -B research/byte_amsco/astra/controls.py
python3 -B research/byte_amsco/astra/controls.py --regenerate /tmp/byte-amsco-controls.json
```

The default command performs standard-library source/dependency/structure checks. Regeneration performs the actual synthetic cryptography using the separately controlled seven-backend runtime.


## Completed binary CFB8 cascade search

The [cascade result](iv_independent/cascade/target/RESULTS.md) closes all 22,764 registered path endpoints, with exact depth counts 28, 784 and 21,952. Every case fails the A105 necessary byte condition. There are zero retained candidates, empty intervals or cases requiring the strict FSA stage. Rejected intermediate endpoints still expanded. The finite exclusion covers only the seven fixed-key CFB8 backends, depths one through three, four outer orientations and four interlayer involutions, under the proved interval recurrence for arbitrary independent layer IVs.

The original ledger contains 23,151,009 bytes, SHA-256 `2eb167a4ec5503a3b27fe84dd4a3a96f781443eade8d78bfefdab9ff01aacf7e`. The [1,562,439-byte lossless pack](iv_independent/cascade/target/target_results.pack.json), SHA-256 `31b57482ed2898a901509cd4d9eb4c5da2da3aa9918ebac3aee7150a4dcd1da7`, preserves every original byte in a zlib/base85 JSON envelope. The standard-library [decoder and verifier](iv_independent/cascade/target/pack_results.py) bounds decompression, checks the exact original hash, source/gate identities, complete Cartesian ID set, every interval geometry, all summaries and all 22,764 stored invalid-byte witness structures. Root ran it and separately confirmed byte-for-byte equality with the full local ledger.

```sh
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/pack_results.py
python3 -S -B research/rev7-20260909-codex/iv_independent/cascade/target/pack_results.py --unpack /tmp/cascade-target-results.json
```

This verifies lossless reconstruction, integrity and accounting of the controlled run; it is not a second target cryptographic replay. No candidates existed for the driver's independent candidate replay. The driver did not record elapsed time, so no timing is inferred. No plaintext or outside-interval bytes were recovered, and interposed encodings, transpositions, other modes, keys or depths remain outside scope.


## Width-13 six-column byte-AMSCO proof

The [width-13 proof](../byte_amsco/astra/prefix13/README.md) adds a necessary filter for inverse byte-AMSCO followed by eight-byte CFB8 decryption. At length 546, width 13 produces 28 complete rows. Alternating one/two-byte cells give every observed column exactly 42 bytes. Assigning six observed chunk ranks to the first six natural columns fixes the first nine ciphertext bytes in every row, including a complete CFB8 window and its next byte. Any computed ninth plaintext byte outside A105 rejects all 7! completions of that prefix, independent of the external IV. Thus 1,235,520 six-rank assignments partition all 13! column orders in each fixed start/orientation/backend context.

Exhaustive width-7 and width-9 controls compare classifications and factorial partitions against a materialized full inverse, using a deterministic synthetic block function. Historical DES, Blowfish, Blowfish compatibility and RC2 are separately exercised in bounded width-13 plants: 1,025 assignments, both starts and two IVs, with exact computed-byte tuple comparisons and the same 28 true plaintext ninth bytes. These controls distinguish geometric accounting from historical primitive evidence.

Root reviewed the proof and independently regenerated the complete [ledger](../byte_amsco/astra/prefix13/controls.json), SHA-256 `7729b861b73e2326bffb33caf1ba2951278bc8d1d0accee2b61973bed3c10de7`. Every deterministic field matched; only six temporary source-build path/hash fields differed. No target was read or evaluated, and a retained prefix would remain only a necessary-condition candidate.

```sh
python3 -S -B research/byte_amsco/astra/prefix13/controls.py
python3 -B research/byte_amsco/astra/prefix13/controls.py --regenerate /tmp/prefix13-controls.json
```


## Indexed byte-AMSCO all-IV search controls

The [indexed search engine](../byte_amsco/astra/search/README.md) precomputes natural-byte column/offset maps and gathers one ciphertext prefix shared across the seven backends. Each backend begins at its IV-free block boundary and stops at the first impossible A105 or strict-FSA byte. A retained case reaches the true stream end in state 0 and keeps its full suffix and exact order. The prospective widths-2-through-9 grid contains 3,272,896 transforms and 22,910,272 backend contexts.

The [control ledger](../byte_amsco/astra/search/controls.json), SHA-256 `7431dbdf75e8d9e7389063d59b5e33260e487e11befd0898170ea46085ad0a70`, records 43,600 independent inverse comparisons; plants for all seven backends, both starts and four orientations; 28 exact independent early-failure checks; and 21 incoming-state/terminal fixtures. Root independently regenerated the whole package. All deterministic fields matched, including the 140,000-context benchmark digest `5fc94e5640aac0071f64833a2a0a016c4a490eab877e44761b1042122bf83551`; only four timing-derived fields differed.

The original benchmark processed 20,000 width-9 orders in 0.482 seconds, while root measured 0.503 seconds. Linear full-grid projections are about 79–82 seconds before target checkpointing, survivor output and other overhead. Portable Python is adequate for this bounded model. This snapshot contains no target driver, gate or Rev7 evaluation.

```sh
python3 -S -B research/byte_amsco/astra/search/controls.py
python3 -B research/byte_amsco/astra/search/controls.py --regenerate /tmp/byte-amsco-search-controls.json
```


## Controlled byte-AMSCO target harness

The [target harness](../byte_amsco/astra/search/target/README.md) specifies 64 geometries at widths 2–9, both starts and four orientations. It requires every width! order and every seven-backend context, totalling 3,272,896 transforms and 22,910,272 contexts. The driver records class/backend counters, a deterministic digest over every negative callback, three witness examples per geometry and all complete survivors. Survivors receive independent full-CFB decryption and exact re-encryption under two IVs. A digest records callback output; it does not independently prove execution.

Two synthetic complete grids exercise the production driver callbacks: a width-2 AES plant and width-3 Loki97 plant. All eight orders and 56 contexts complete, with 54 negatives and the two expected retained cases. Both survivors pass exact two-IV replay. Root independently regenerated the [11,544-byte ledger](../byte_amsco/astra/search/target/controls.json), reproducing SHA-256 `cecad094eff30630f4cafd7c8352f9a0c651bcdf096b443cdb20840dc8c733f8` byte for byte. The frozen driver SHA-256 is `a3b865878f889799fbbebb7d8de3956677fdad0696ee96434f7e30982cde3ec3`.

```sh
python3 -S -B research/byte_amsco/astra/search/target/controls.py
python3 -B research/byte_amsco/astra/search/target/controls.py --regenerate /tmp/byte-amsco-target-controls.json
python3 -S -B research/byte_amsco/astra/search/target/run_target.py --selftest
```

This source/control snapshot has no target gate or evaluation. Gate creation follows FABLE preregistration and execution requires separate root GO. Existing outputs/checkpoints are refused; no cap or resume mode is allowed.


## Frozen general byte-AMSCO gate

Following FABLE message 144, the [general byte-AMSCO gate](../byte_amsco/astra/search/target/target_gate.json) freezes the reviewed 64-geometry, 22,910,272-context specification and all driver, engine, proof, control, source, key-convention and canonical-input artifacts. Gate SHA-256 is `61793d92916e57959f2cca9f5df32df8cc1cdcf4e06781eaa3f19193e33a49c2`. Root's MDX-hash-only selftest passed with the gate present. This snapshot precedes target execution and a separate GO.


## Native width-13 prefix controls

The [native first-six prefix engine](../byte_amsco/astra/prefix13/native/README.md) implements the accepted byte-AMSCO proof for DES, standard Blowfish, historical Blowfish compatibility and historical RC2, with the fixed eight-byte-block key conventions. Every retained prefix keeps its six ranks and computed ninth-byte tuple; all examined, rejected, survivor and unexamined factorial weights are recorded.

The [control ledger](../byte_amsco/astra/prefix13/native/native_controls.json), SHA-256 `97eb5e5783c8c0aedfe98c27e112da8ffb2a641fa284a6ff3690de867be62766`, records exact native/Python parity for 524,160 complete prefixes, bounded width-13 comparisons and separate true planted assignments, 256 block vectors, eight complete byte-value CFB8 streams and malformed-input checks. Every complete parity grid has positive and rejected prefixes. Eight synthetic timing samples examined one million prefixes each; all retained zero, so count-only timing lost no survivor payload.

Root reviewed the source and independently regenerated all controls. Every nontiming field matched exactly. The executable hash reproduced as `704f5f431b0b92136624eaba960605f2a652e8818a42b86a8a44e14566722b04`, and the RC2 object as `022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e`. Both are temporary build evidence; source, provenance and build commands are published, without binaries. The original and root timing samples project about 5.21 and 5.22 native seconds respectively for 39,536,640 prefixes across 32 prospective contexts, excluding orchestration and verification.

```sh
python3 -S -B research/byte_amsco/astra/prefix13/native/native_controls.py
python3 -B research/byte_amsco/astra/prefix13/native/native_controls.py --regenerate /tmp/prefix13-native-controls.json
```

These controls do not read Rev7 or register a width-13 target. The filter remains a necessary A105 condition; surviving prefixes would not be complete orders or recovered plaintexts.


## Completed general byte-AMSCO search

The [completed result](../byte_amsco/astra/search/target/RESULTS.md) covers all 64 registered geometries, 3,272,896 column orders and 22,910,272 backend contexts. Every case rejects: 22,463,286 at A105 and 446,986 at a strict FSA transition. No candidates or unexamined contexts remain. This is a finite exclusion for byte-unit AMSCO widths 2–9, two alternating starts, four orientations, seven fixed-key CFB8 backends and the specified text endpoint, independent of every external IV.

The [230,874-byte ledger](../byte_amsco/astra/search/target/target_results.json) has SHA-256 `baf3fc16f2eb84008b75fc80521502134945fdeece075183fa61050c19779cdd`. Root reviewed and ran the [portable verifier](../byte_amsco/astra/search/target/verify_results.py), checking all pinned artifacts, canonical orientations, Cartesian cell IDs, factorial/backend/class accounting and zero retained contexts. This does not repeat the negative cryptographic enumeration. The driver did not record elapsed time.

```sh
python3 -S -B research/byte_amsco/astra/search/target/verify_results.py
```

## Controlled width-13 byte-AMSCO target harness

The [inert width-13 harness](../byte_amsco/astra/prefix13/native/target/README.md) defines 32 contexts: four eight-byte-block backends, both starts and four orientations. Each cell enumerates all 1,235,520 six-column assignments; the grid totals 39,536,640 prefixes. Every retained assignment and all 28 computed ninth plaintext bytes are kept and independently replayed. Each cell partitions 13! full orders, with weight 7! per prefix. A surviving prefix leaves those full orders unresolved.

Root reviewed the driver and independently regenerated the [synthetic callback ledger](../byte_amsco/astra/prefix13/native/target/driver_controls.json) byte for byte, SHA-256 `f86b6eb63765565849838e4ff0da843f34fa5e4a3e0bbab40813cdc32bfda487`. Two complete width-7 plants contain 135 and 145 survivors respectively, all independently replayed. Temporary native binary and RC2 object hashes match the accepted control builds exactly. These tests exercise the same execute_cell function as the future target.

```sh
python3 -S -B research/byte_amsco/astra/prefix13/native/target/driver_controls.py
python3 -B research/byte_amsco/astra/prefix13/native/target/driver_controls.py --regenerate /tmp/prefix13-driver-controls.json
```

This snapshot has no width-13 target gate or evaluation. FABLE preregistration, the frozen gate and separate root GO precede the target run. The driver refuses existing outputs and has no cap, count-only target mode or resume.


## Frozen width-13 byte-AMSCO target gate

Following FABLE preregistration message 147, the [width-13 gate](../byte_amsco/astra/prefix13/native/target/target_gate.json) freezes all 32 contexts, driver/build/control/proof/source artifacts and canonical input identities. Its SHA-256 is `4edfe5ffbced9ca4167f106a9b0c577257cd7292e047f1ffd4d634e808c9880c`. Root's gate-only selftest passed without extracting or evaluating target ciphertext. This publication precedes a separate root GO and target execution.

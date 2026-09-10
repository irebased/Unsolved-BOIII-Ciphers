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

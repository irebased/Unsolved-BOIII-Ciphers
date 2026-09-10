# Whole-radix decimal to checkerboard scope audit

```json
{"identity":"ASTRA","status":"source/history audit complete","target_evaluated":false,"recommendation":"do not repeat the direct ordinary 26-cell experiment"}
```

## Finding

The proposed path has already been reported as tested in the exact direct form that matters:

```
one oriented Rev7 hex string-> one arbitrary-precision integer read in base 16-> canonical decimal digit string-> unchanged or reversed digit direction-> ordinary two-header straddling-checkerboard parse
```

The base-16 case is a subset of the recorded bases 16 through 36. The recorded grid used all four direct orientations, both decimal directions, every two-header choice, both edge phases, and an arbitrary injective assignment of complete cells to 26 symbols. It found that every parse needs at least 27 distinct complete code cells: 15,118 need 28 and two need 27. An exact Rev3 keyed board with the same injective 26-symbol semantics is a subset of that arbitrary 26-cell family, so running only the Rev3 board would duplicate a stronger capacity test.

This conclusion comes from the frozen public history, not a newly rerun target or a recovered worker. The reported result ledger SHA-256 is `d348bff3be232f4165c6aee1c5360a85f441b374c6605d1a2f4bc4ff002b8b96`, but the run kit is not present in the reviewed checkout. This audit therefore classifies it as a specifically scoped historical result reported as reviewed, while retaining the source-availability limitation.

## What the local whole_numeric package does

The newer `whole_numeric` package is adjacent but different. Its `int_to_digits` implementation is at lines 53-61 of `controls.py`; `parse_fixed3` at lines 84-94 interprets fixed three-digit byte values, and `parse_variable_dp` at lines 97-133 interprets canonical two/three-digit byte values. Neither is a straddling checkerboard. Its 96-cell result covers whole-integer base-8/base-10 digit strings parsed directly as allowed bytes.

Thus it would be wrong to cite `whole_numeric` alone as checkerboard coverage. The checkerboard coverage is the earlier `R7-20260909-root-005` result in the frozen issue snapshot.

## Reversal and leading-zero scope

The recorded direct experiment explicitly includes both digit directions and "both possible edge alignments [that] allow arbitrary zero loss." For an ordinary two-header board this is the relevant capacity treatment:

- if digit zero is a one-digit cell, prepended zeros add repetitions of one cell and leave the subsequent parse phase unchanged;
- if zero is a header, the two possible starting phases cover the parity of a zero run, after which additional `00` pairs only repeat a cell;
- adding repeated prefix cells cannot reduce the number of distinct complete cells already required by the stabilized suffix.

That supports the prior **26-cell capacity exclusion** without selecting a specific number of restored zeros. It does not mean every possible plaintext prefix was enumerated or scored. The history also reports a later 0-14 restored-zero grid around ZOMBIES/Zombies column operations; that is a different composition and should not be substituted for the direct capacity proof.

The separate expanded-board audit covers two/three-header and numeric-escape grammars over the same 168 whole-integer decimal rows and edge offsets. It reports 635,040 alignments and leaves 96 with at most 26 ordinary classes. Those survivors were structural cases, not recovered symbol assignments or plaintexts.

## Corpus support

Rev3 confirms that digit-valued intermediates can feed a classical layer. Its documented original route reverses, performs decimal/octal representation steps, then uses a straddling checkerboard keyed `fkmcpdyehbigqrosazlutjnwvx` with spare positions 3 and 7. Its simpler route maps ten glyphs to digits by order of appearance and tries checkerboard decoding in both directions. These are evidence for considering the family, but they are not evidence that Rev7 uses the same board or representation.

## Remaining scope

No small, corpus-supported direct ordinary-checkerboard rerun is justified from this lead. The honest open dimensions are:

- boards with 27 or 28 output symbols;
- homophonic cells or other noninjective output semantics;
- source-defined expanded checkerboards beyond the reported capacity bounds;
- arithmetic, transposition, or another layer between decimal rendering and checkerboard parsing;
- chunked, limb-local, or per-byte decimal serialization rather than one whole integer;
- other token grammars or a changed representation boundary.

Those are different models. "Unknown board" by itself is not an uncovered ordinary 26-cell case, because the prior test was already independent of the 26-symbol assignment. A future experiment should require a concrete source-backed expanded grammar or an explicit intervening transform; this audit does not recommend a new target run.

## Evidence and hashes

- `notebook-snapshot.json`, comment 8: exact `R7-20260909-root-005` scope, counts, boundary controls, limits and unavailable run-kit hash. SHA-256 `ad67d420644b203a8f952d84f93d4755578c079aa9b98952cab8a73ccc3461ab`.
- The same snapshot, comment 19: source-defined expanded-board audit and its exact 635,040-alignment scope.
- `coverage/REPORT.md`, lines 16-23: whole-integer decimal/checkerboard coverage and the distinct chunk/per-byte decimal gaps. SHA-256 `2a5d20ae6eee4d2ddf2a8ba9ef7bd208e43f0f372fac29e5305f3bdf6918c57e`.
- `whole_numeric/controls.py`: direct numeric byte-parser implementation, SHA-256 `937dfea250ca67e6788263db4431d4b324c08d807eade51c034755bbe745408e`.
- `whole_numeric/README.md`: exact 96-cell adjacent scope, SHA-256 `3e5d66ba62e19d6d61b93c1373d00ae7d90168d8962b3e0a8e3d19927cc96b0e`.
- `lavender/src/content/docs/ciphers/bo3/rev/rev3.mdx`, lines 24-38: documented sibling construction. SHA-256 `0185f674db09dfe542de8ecf2880cf83690cc8331001ebfefa65ddc4f965a243`.
- `coverage/rev3_classical_scope/INVENTORY.md`, lines 15 and 21-30: prior distinction between numeric direct parsing and checkerboard/fractionation. SHA-256 `8e92660141e545d4371c77478792c4ed7b854fd5503ab9557b775e4402aaab5d`.

No Rev7 bytes were extracted, transformed, or evaluated in this audit.

# ASTRA grouped-decoder prefix-alignment audit

This is a source-only audit prompted by the observation that discarding an IV-dependent CFB8 prefix changes the local origin used by a subsequent fixed-width decoder. It performed no Rev7 computation and changed no earlier experiment.

## Result

The warning is mathematically valid, but the reviewed accepted ASTRA experiments do not contain the vulnerable pipeline. No reviewed target first discarded an unknown-IV CFB8 prefix and then decoded fixed-three decimal or Base64 groups from suffix-local offset zero.

The global-hex `encoded` searches only test membership in named byte alphabets. In `hex_cfb/encoded/run_encoded.py`, lines 33–38 define the sets, lines 56–59 implement a one-state membership transition, and line 80 rechecks membership. The Base64 extension uses the same membership predicate. These are necessary detectors, not Base64/decimal decoders. Phase cannot cause them to reject an otherwise alphabet-valid suffix, although a retained result would still require a real decoder.

The all-IV cascade target similarly applies A105 and a boundary-aware UTF-8 automaton (`iv_independent/cascade/target/run_target.py`, lines 66–85). The byte-bag replay counts disallowed bytes after the skip (`coverage/fable_bytebag_replay/verify_outputs.py`, line 22). Neither groups the suffix. The cascade proof also explicitly excludes interposed Base64/numeric encodings (`iv_independent/cascade/proof.py`, line 107).

The actual grouped decoders consume complete buffers:

- `whole_numeric/controls.py`, lines 442–467, converts the complete oriented hex string into one integer and parses its complete rendered digit stream. It has no CFB step or prefix cut.
- `hex_cfb/native_siblings/controls.py`, lines 68–83, and `sources/rev9_source/controls.py`, lines 42–51, are solved sibling controls with known fixed IVs. Their hex, decimal, and Base64 transforms consume complete layer outputs.

## Alignment rule and witness

For a fixed group width `g`, a known interval beginning at absolute offset `L` must begin grouping at an offset congruent to the original origin modulo `g`. When the original origin is zero, discard `(-L) mod g` additional leading bytes before decoding. An incomplete right-edge group must also be handled explicitly. If the origin itself is unknown, its justified phases must be enumerated.

The synthetic fixed-three stream encodes bytes `A` through `Z` as three decimal digits each. Cuts of 8, 16, and 32 bytes have phases 2, 1, and 2 modulo three. Parsing those suffixes at local zero fails or groups the wrong characters; trimming respectively 1, 2, and 1 bytes reaches the next original triplet boundary and recovers the exact remaining bytes.

Ordinary Base64 has width four. The registered CFB block-size cuts 8, 16, and 32 are all phase zero modulo four, and the control confirms exact suffix decoding for a complete phase-aligned fixture. This does not make every arbitrary known interval Base64-decodable: right-edge alignment, padding, and interposed transforms still need explicit handling.

## Reproduction

```sh
python3 -B research/rev7-20260909-codex/coverage/prefix_group_alignment_audit/audit.py
```

The verifier pins every reviewed source and communication record by SHA-256, rebuilds both witnesses, and compares the complete ledger. This audit covers the named accepted sources, not unpublished or superseded drafts and not FABLE code.

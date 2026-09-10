# Width-13 byte-AMSCO first-six target result

Identity: ASTRA.

The single preregistered invocation completed all 32 contexts:

- DES, Blowfish, Blowfish compatibility, and RC2;
- continuous cell starts 1/2 and 2/1;
- forward, full-hex-reverse, byte-reverse, and nibble-swap orientations;
- width 13, length 546, 28 rows, and equal 42-byte observed chunks.

Every cell examined all `P(13,6) = 1,235,520` ordered assignments of observed chunks to the first six natural AMSCO columns. Every assignment failed the necessary A105 test in at least one row. There were no retained prefixes and no unexamined prefixes.

Aggregate execution:

- cells: 32;
- prefixes examined: 39,536,640;
- prefixes rejected: 39,536,640;
- survivor prefixes: 0;
- unexamined prefixes: 0;
- native block calls: 67,022,745;
- summed native time: 5.300495 seconds;
- summed cell wall time: 5.726155248 seconds.

Within each cell, a rejected six-rank prefix has completion weight `7! = 5,040`. The exact rejected weight is therefore `13! = 6,227,020,800` full column orders per cell. These weights belong to overlapping cipher, start, and orientation contexts and are not additive independent permutation evidence.

## Reproduction and integrity

The exact authorized command was:

```sh
python3 -B research/byte_amsco/astra/prefix13/native/target/run_target.py --run-target
```

Artifacts:

- target result: 69,972 bytes, SHA-256 `61fff04ed7d8e61f2d74986c086357606c8b9e2877667184ea4d008928329541`;
- target gate: `4edfe5ffbced9ca4167f106a9b0c577257cd7292e047f1ffd4d634e808c9880c`;
- target driver: `166edaadd98a95abfa6c6336652be4d2218491d548335f6714d048c7e491fa59`;
- controlled native source: `f9c731e222381597dcb03d00155549f12fb6d82923975b13f2a18d3c05e631d0`;
- controlled native ledger: `97eb5e5783c8c0aedfe98c27e112da8ffb2a641fa284a6ff3690de867be62766`;
- temporary native binary: `704f5f431b0b92136624eaba960605f2a652e8818a42b86a8a44e14566722b04`;
- temporary historical RC2 object: `022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e`.

The result records Apple clang 21.0.0 and OpenSSL 3.6.3. It preserves both temporary build commands, their output, all 32 atomic cell records, counters, hashes, and source provenance.

Portable read-only verification:

```sh
python3 -S -B research/byte_amsco/astra/prefix13/native/target/verify_results.py
```

By default, the verifier needs only the published combined result and source package. It pins the result, validates every target-gate pin through the frozen driver, checks the canonical MDX and controlled dependencies, reconstructs all four orientations, validates the exact ordered 32 combined cell records, and replays all factorial accounting. It does not compile a binary or rerun the 39,536,640-prefix search. When the unpublished local checkpoint directory is available, `--check-local-cells` additionally requires each of the 32 atomic JSON files to equal its combined record exactly.

## Scope of the negative result

For each registered context, no inverse byte-unit AMSCO width-13 full order can yield A105 at all 28 tested row-ninth positions under the fixed backend and key, regardless of the external eight-byte IV. Since membership in A105 is necessary for the registered text endpoint, this closes that finite model.

The result does not test other widths, insertions or deletions, character-unit historical PHP processing, different keys, other ciphers, altered CFB alignment, or interposed encodings. It does not recover an IV or full plaintext. The controlled enumerator was independently checked on synthetic grids, but the portable result verifier is an integrity and accounting replay rather than a second 39.5-million-prefix negative enumeration.

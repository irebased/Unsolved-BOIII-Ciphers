# Byte-unit AMSCO geometry controls (ASTRA)

This package defines a binary AMSCO analogue over byte tokens. It is synthetic-only: neither the Rev7 ciphertext nor a target gate is read, parsed, or evaluated.

A natural byte stream is split into cells of one and two bytes with one continuous alternation across row boundaries. Cells are placed row-major in a matrix of the selected width. The forward transform concatenates complete columns in the selected column order. The inverse derives every natural cell size from the total byte length, sums the byte length of each natural column, partitions the observed stream in read-order, and restores cells in natural order.

The forward and inverse are both retained because they serve different purposes. A future search needs only the inverse. The forward transform is required to generate plants and prove that inversion reconstructs the exact pre-transposition bytes. The implementations do not share an index-map generator. The control file also contains separate tuple-token forward and inverse oracles.

If the input ends before a nominal two-byte cell is full, that final cell has one byte. Its shortened size contributes to the natural column's byte length before observed column chunks are assigned. For the registered 546-byte fixture, 546 is exactly 182 cycles of three bytes: there are 364 cells. A start of 1,2 ends in a two-byte cell; a start of 2,1 ends in a one-byte cell. No cell is shortened at length 546, but explicit shorter fixtures exercise truncation.

The four orientations are byte interpretations of the displayed hexadecimal form: forward, reversal of all hex symbols, reversal of byte order, and nibble swap within every byte. All are involutions.

## Controls

The control regeneration performs:

- exhaustive small cases for lengths 0 through 24, widths through 6, every column permutation, and both starting patterns;
- agreement of the production forward and inverse with independent tuple-token oracles;
- exact prefix reconstruction through the inverse layout;
- all widths 2 through 9 at length 546, including cell counts and natural-column byte lengths;
- explicit shortened-final-cell fixtures;
- planted CFB8 to byte-AMSCO to hex chains for all seven accepted backends, all four orientations, and two unrelated IVs per backend;
- exact recovery of the pre-transposition ciphertext, IV-independent suffix equality from each block boundary, and exact full re-encryption; and
- a bounded 50,000-order Python geometry benchmark that gathers only the first 64 recovered bytes.

Default verification is standard-library only and does not rebuild or replay cryptography:

```sh
python3 -S -B research/byte_amsco/astra/controls.py
```

Regeneration needs PyCryptodome and clang because it invokes the accepted seven-backend runtime. It requires a new path and refuses overwrites:

```sh
python3 -B research/byte_amsco/astra/controls.py \
  --regenerate /tmp/byte-amsco-controls.json
```

## Prospective target scope

Widths 2 through 9, both starts, every column order, and four orientations contain exactly 3,272,896 transforms. This package does not run that grid.

A target implementation should precompute cell metadata for each width and start, gather only ciphertext bytes needed for the current CFB8 window, and stop at the first impossible endpoint constraint. Reconstructing all 546 bytes for every transform is unnecessary. The included Python layout benchmark projects about 262 seconds for geometry alone on this host, before cipher calls and endpoint checks; it is deliberately a baseline rather than a proposed target implementation.

This binary analogue is not equivalent to the historical PHP AMSCO tool, which processes characters. It also does not establish a historical frontend, key, IV, cipher, or pipeline placement.
